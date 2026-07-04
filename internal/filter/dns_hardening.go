package filter

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Anti-exfiltration hardening for the DNS proxy. All DNS is already forced through
// the proxy, so these checks close the remaining tunneling channels: bulky or
// oddly-shaped outbound qnames, bulky TXT/NULL answers inbound, and bulk query
// volume. Deliberately no entropy heuristics: CDN hashes and DKIM lookups make
// them false-positive prone; the deterministic length/size caps below catch the
// same tunnels without guessing.
const (
	// exfilMaxQname is below the RFC's 253: legitimate names longer than this are
	// vanishingly rare, while DNS tunnels need long names for bandwidth.
	exfilMaxQname = 220
	// exfilMaxLabel is below the RFC's 63: base32/64 exfil chunks typically fill
	// the label; real hostnames rarely exceed this.
	exfilMaxLabel = 56

	maxTXTPayloadBytes = 1024
	maxResponseBytes   = 4096

	dnsRateLimitQPS   = 50
	dnsRateLimitBurst = 100

	rateLimiterMaxSources = 4096
	rateLimiterIdleEvict  = time.Minute
)

// checkExfilQuery returns a non-empty reason when a query looks like a tunnel/exfil channel.
func checkExfilQuery(qname string, qtype uint16) string {
	if qtype == dns.TypeNULL {
		return "null-query"
	}

	if len(qname) > exfilMaxQname {
		return "qname-too-long"
	}

	for label := range strings.SplitSeq(qname, ".") {
		if len(label) > exfilMaxLabel {
			return "label-too-long"
		}
	}

	return ""
}

// checkExfilResponse returns a non-empty reason when an upstream answer looks like
// a tunnel payload (oversized message, NULL records, bulky TXT rdata).
func checkExfilResponse(resp *dns.Msg) string {
	if resp == nil {
		return ""
	}

	if resp.Len() > maxResponseBytes {
		return "response-too-large"
	}

	txtBytes := 0

	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.NULL:
			return "null-record"
		case *dns.TXT:
			for _, s := range record.Txt {
				txtBytes += len(s)
			}
		}
	}

	if txtBytes > maxTXTPayloadBytes {
		return "txt-payload-too-large"
	}

	return ""
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// dnsRateLimiter is a per-source token bucket to blunt bulk exfil and protect the
// proxy itself. Enforced regardless of audit/learning mode.
type dnsRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time
}

func newDNSRateLimiter() *dnsRateLimiter {
	return &dnsRateLimiter{
		mu:      sync.Mutex{},
		buckets: make(map[string]*tokenBucket),
		now:     time.Now,
	}
}

func (l *dnsRateLimiter) allow(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	bucket, ok := l.buckets[source]
	if !ok {
		if len(l.buckets) >= rateLimiterMaxSources {
			l.pruneLocked(now)
		}

		bucket = &tokenBucket{tokens: dnsRateLimitBurst, last: now}
		l.buckets[source] = bucket
	}

	bucket.tokens += now.Sub(bucket.last).Seconds() * dnsRateLimitQPS
	if bucket.tokens > dnsRateLimitBurst {
		bucket.tokens = dnsRateLimitBurst
	}

	bucket.last = now

	if bucket.tokens < 1 {
		return false
	}

	bucket.tokens--

	return true
}

func (l *dnsRateLimiter) pruneLocked(now time.Time) {
	for src, bucket := range l.buckets {
		if now.Sub(bucket.last) > rateLimiterIdleEvict {
			delete(l.buckets, src)
		}
	}
}
