// Package nftables provides nftables integration.
package nftables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/g0lab/g0efilter/internal/filter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	minPacketSize = 20
)

var errPortOutOfRange = errors.New("port out of range")

// Version returns the nftables version string.
func Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "nft", "--version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get nft version: %w", err)
	}

	// Output is typically "nftables v1.0.9 (Spark In The Dark)"
	version := strings.TrimPrefix(strings.TrimSpace(string(out)), "nftables ")

	return version, nil
}

// parsePort validates and converts a port string to an integer between 1 and 65535.
func parsePort(s, name string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid %s port %q: %w", name, s, err)
	}

	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%w: %s port %d", errPortOutOfRange, name, port)
	}

	return port, nil
}

// splitByFamily partitions a flat IP/CIDR allowlist into IPv4 and IPv6 slices.
func splitByFamily(allowlist []string) ([]string, []string) {
	var v4, v6 []string

	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}

			if ipnet.IP.To4() != nil {
				v4 = append(v4, entry)
			} else {
				v6 = append(v6, entry)
			}

			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			v4 = append(v4, entry)
		} else {
			v6 = append(v6, entry)
		}
	}

	return v4, v6
}

// ApplyNftRulesAuto applies nftables rules using port numbers from environment variables or defaults.
func ApplyNftRulesAuto(allowlist []string, httpsPortStr, httpPortStr string) error {
	dnsPortStr := strings.TrimSpace(os.Getenv("DNS_PORT"))
	if dnsPortStr == "" {
		dnsPortStr = "53"
	}

	return ApplyNftRules(allowlist, httpsPortStr, httpPortStr, dnsPortStr)
}

func validateAndParseRuleset(ctx context.Context, ruleset string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)

	var out bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nft dry-run failed: %w\nOutput:\n%s", err, out.String())
	}

	return nil
}

func applyRuleset(ctx context.Context, ruleset string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)

	var out bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w\nOutput:\n%s", err, out.String())
	}

	return nil
}

// ApplyNftRulesWithContext generates and applies the nftables ruleset using the provided context.
func ApplyNftRulesWithContext(
	ctx context.Context,
	allowlist []string,
	httpsPortStr,
	httpPortStr,
	dnsPortStr string) error {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("FILTER_MODE")))
	if mode == "" {
		mode = filter.ModeHTTPS
	}

	if len(allowlist) == 0 {
		allowlist = []string{"127.0.0.1"}
	}

	httpsPort, err := parsePort(httpsPortStr, "HTTPS")
	if err != nil {
		return err
	}

	httpPort, err := parsePort(httpPortStr, "HTTP")
	if err != nil {
		return err
	}

	dnsPort, err := parsePort(dnsPortStr, "DNS")
	if err != nil {
		return err
	}

	v4, v6 := splitByFamily(allowlist)

	ruleset := GenerateNftRuleset(v4, v6, httpsPort, httpPort, dnsPort, mode)
	if !strings.HasSuffix(ruleset, "\n") {
		ruleset += "\n"
	}

	_ = deleteTableIfExists(ctx, "ip", "g0efilter_v4")
	_ = deleteTableIfExists(ctx, "ip", "g0efilter_nat_v4")
	_ = deleteTableIfExists(ctx, "ip6", "g0efilter_v6")
	_ = deleteTableIfExists(ctx, "ip6", "g0efilter_nat_v6")

	err = validateAndParseRuleset(ctx, ruleset)
	if err != nil {
		return err
	}

	return applyRuleset(ctx, ruleset)
}

// ApplyNftRules applies nftables rules using a background context.
func ApplyNftRules(allowlist []string, httpsPortStr, httpPortStr, dnsPortStr string) error {
	return ApplyNftRulesWithContext(context.Background(), allowlist, httpsPortStr, httpPortStr, dnsPortStr)
}

// generateDNSFilterRules creates nftables filter rules for DNS mode that block non-allowlisted traffic.
func generateDNSFilterRules(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip daddr 127.0.0.1 udp dport %d accept
        ip daddr 127.0.0.1 tcp dport %d accept

        # Allow ping to allow-listed destinations
        icmp type echo-request ip daddr @allow_daddr_v4 accept
    }
}
`, allowSet, dnsPort, dnsPort)
}

// generateHTTPSFilterRules creates nftables filter rules for HTTPS mode with logging and allowlist enforcement.
func generateHTTPSFilterRules(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v4 {
        type filter hook output priority filter; policy drop;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local proxies on 127.0.0.1
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTP proxy
        ip daddr 127.0.0.1 tcp dport %d accept    # HTTPS proxy

        # Allow ping to allow-listed destinations
        icmp type echo-request ip daddr @allow_daddr_v4 accept

        # Allow and log allow-listed destinations
        ip daddr @allow_daddr_v4 log prefix "allowed" group 0
        ip daddr @allow_daddr_v4 accept

        # Log and drop everything else
        log prefix "blocked" group 0
        drop
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateDNSNATRules creates nftables NAT rules that redirect all DNS traffic to the local DNS proxy.
func generateDNSNATRules(dnsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_nat_v4 {
    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Exempt direct access to the local DNS proxy
        ip daddr 127.0.0.1 udp dport 53 return
        ip daddr 127.0.0.1 tcp dport 53 return
        ip daddr 127.0.0.1 udp dport %d return
        ip daddr 127.0.0.1 tcp dport %d return

        # Redirect ALL DNS (UDP/TCP 53) to local DNS proxy
        udp dport 53  log prefix "dns_redirected" group 0
        udp dport 53  redirect to :%d
        tcp dport 53  log prefix "dns_redirected" group 0
        tcp dport 53  redirect to :%d
    }
}
`, dnsPort, dnsPort, dnsPort, dnsPort)
}

// generateHTTPSNATRules creates nftables NAT rules that redirect HTTP/HTTPS to local proxies for non-allowlisted IPs.
func generateHTTPSNATRules(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip g0efilter_nat_v4 {
    set allow_daddr_v4 {
        type ipv4_addr
        flags interval
        elements = {%s}
    }

    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Return if allow-listed IP
        ip daddr @allow_daddr_v4 return

        # Redirect HTTP (80) to local HTTP proxy
        tcp dport 80  log prefix "redirected" group 0
        tcp dport 80  redirect to :%d

        # Redirect HTTPS (443) to local HTTPS proxy
        tcp dport 443 log prefix "redirected" group 0
        tcp dport 443 redirect to :%d
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateHTTPSFilterRulesV6 creates IPv6 nftables filter rules for HTTPS mode.
func generateHTTPSFilterRulesV6(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_v6 {
    set allow_daddr_v6 {
        type ipv6_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v6 {
        type filter hook output priority filter; policy drop;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local proxies on ::1
        ip6 daddr ::1 tcp dport %d accept    # HTTP proxy
        ip6 daddr ::1 tcp dport %d accept    # HTTPS proxy

        # Allow ping to allow-listed destinations
        icmpv6 type echo-request ip6 daddr @allow_daddr_v6 accept

        # Allow and log allow-listed destinations
        ip6 daddr @allow_daddr_v6 log prefix "allowed" group 0
        ip6 daddr @allow_daddr_v6 accept

        # Log and drop everything else
        log prefix "blocked" group 0
        drop
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateHTTPSNATRulesV6 creates IPv6 nftables NAT rules for HTTPS mode.
func generateHTTPSNATRulesV6(allowSet string, httpPort, httpsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_nat_v6 {
    set allow_daddr_v6 {
        type ipv6_addr
        flags interval
        elements = {%s}
    }

    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Return if allow-listed IP
        ip6 daddr @allow_daddr_v6 return

        # Redirect HTTP (80) to local HTTP proxy
        tcp dport 80  log prefix "redirected" group 0
        tcp dport 80  redirect to :%d

        # Redirect HTTPS (443) to local HTTPS proxy
        tcp dport 443 log prefix "redirected" group 0
        tcp dport 443 redirect to :%d
    }
}
`, allowSet, httpPort, httpsPort)
}

// generateDNSFilterRulesV6 creates IPv6 nftables filter rules for DNS mode.
func generateDNSFilterRulesV6(allowSet string, dnsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_v6 {
    set allow_daddr_v6 {
        type ipv6_addr
        flags interval
        elements = {%s}
    }

    chain egress_allowlist_v6 {
        type filter hook output priority filter; policy accept;

        # Always allow loopback-bound traffic
        oifname "lo" accept

        # Allow already established connections
        ct state established,related accept

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 accept

        # Allow local DNS proxy on loopback
        ip6 daddr ::1 udp dport %d accept
        ip6 daddr ::1 tcp dport %d accept

        # Allow ping to allow-listed destinations
        icmpv6 type echo-request ip6 daddr @allow_daddr_v6 accept
    }
}
`, allowSet, dnsPort, dnsPort)
}

// generateDNSNATRulesV6 creates IPv6 nftables NAT rules for DNS mode.
func generateDNSNATRulesV6(dnsPort int) string {
	return fmt.Sprintf(`
table ip6 g0efilter_nat_v6 {
    chain output {
        type nat hook output priority -100;

        # Bypass marked traffic (SO_MARK=0x1)
        meta mark 0x1 return

        # Exempt direct access to the local DNS proxy
        ip6 daddr ::1 udp dport 53 return
        ip6 daddr ::1 tcp dport 53 return
        ip6 daddr ::1 udp dport %d return
        ip6 daddr ::1 tcp dport %d return

        # Redirect ALL DNS (UDP/TCP 53) to local DNS proxy
        udp dport 53  log prefix "dns_redirected" group 0
        udp dport 53  redirect to :%d
        tcp dport 53  log prefix "dns_redirected" group 0
        tcp dport 53  redirect to :%d
    }
}
`, dnsPort, dnsPort, dnsPort, dnsPort)
}

// GenerateNftRuleset generates a complete nftables ruleset for the specified mode, ports, and allowlists.
// v4 and v6 are pre-split IPv4 and IPv6 allowlist entries respectively.
func GenerateNftRuleset(v4, v6 []string, httpsPort, httpPort, dnsPort int, mode string) string {
	mode = strings.ToLower(mode)
	if mode != filter.ModeDNS {
		mode = filter.ModeHTTPS
	}

	allowSetV4 := strings.Join(v4, ", ")
	if allowSetV4 == "" {
		allowSetV4 = "127.0.0.1"
	}

	// Generate IPv4 rules
	var filterRules string
	if mode == filter.ModeDNS {
		filterRules = generateDNSFilterRules(allowSetV4, dnsPort)
	} else {
		filterRules = generateHTTPSFilterRules(allowSetV4, httpPort, httpsPort)
	}

	var natRules string
	if mode == filter.ModeDNS {
		natRules = generateDNSNATRules(dnsPort)
	} else {
		natRules = generateHTTPSNATRules(allowSetV4, httpPort, httpsPort)
	}

	ruleset := filterRules + "\n" + natRules

	// Generate IPv6 rules — always redirect port 80/443 through the proxy so
	// domain-based filtering works even when a domain resolves to a AAAA record.
	// If no explicit IPv6 IPs are allowlisted, use ::1 as the placeholder (same
	// pattern as IPv4 using 127.0.0.1) so the set is never empty.
	allowSetV6 := strings.Join(v6, ", ")
	if allowSetV6 == "" {
		allowSetV6 = "::1"
	}

	if mode == filter.ModeDNS {
		ruleset += "\n" + generateDNSFilterRulesV6(allowSetV6, dnsPort)
		ruleset += "\n" + generateDNSNATRulesV6(dnsPort)
	} else {
		ruleset += "\n" + generateHTTPSFilterRulesV6(allowSetV6, httpPort, httpsPort)
		ruleset += "\n" + generateHTTPSNATRulesV6(allowSetV6, httpPort, httpsPort)
	}

	return ruleset
}

func deleteTableIfExists(ctx context.Context, family, table string) error {
	ctxProbe, cancelProbe := context.WithTimeout(ctx, 5*time.Second)
	defer cancelProbe()

	//nolint:gosec // args are hardcoded literals from callers
	probe := exec.CommandContext(ctxProbe, "nft", "list", "table", family, table)

	err := probe.Run()
	if err != nil {
		return nil
	}

	ctxDel, cancelDel := context.WithTimeout(ctx, 3*time.Second)
	defer cancelDel()

	//nolint:gosec // args are hardcoded literals from callers
	del := exec.CommandContext(ctxDel, "nft", "delete", "table", family, table)

	err = del.Run()
	if err != nil {
		return fmt.Errorf("failed to delete table %s %s: %w", family, table, err)
	}

	return nil
}

// StreamNfLog starts streaming netfilter log events using the default logger.
func StreamNfLog() error {
	return StreamNfLogWithLogger(context.Background(), slog.Default())
}

// parseNflogConfig reads NFLOG_BUFSIZE and NFLOG_QTHRESH from environment or returns defaults.
func parseNflogConfig() (uint32, uint32) {
	dfltBuf := uint32(96)
	dfltQ := uint32(50)

	if v := strings.TrimSpace(os.Getenv("NFLOG_BUFSIZE")); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err == nil && n > 0 {
			dfltBuf = uint32(n)
		}
	}

	if v := strings.TrimSpace(os.Getenv("NFLOG_QTHRESH")); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err == nil && n > 0 {
			dfltQ = uint32(n)
		}
	}

	return dfltBuf, dfltQ
}

// setupLogger creates a logger with component, hostname, and tenant_id context fields.
func setupLogger(lg *slog.Logger) *slog.Logger {
	hostname := strings.TrimSpace(os.Getenv("HOSTNAME"))
	if hostname == "" {
		h, err := os.Hostname()
		if err == nil {
			hostname = strings.TrimSpace(h)
		}
	}

	base := []any{"component", "nflog"}
	if hostname != "" {
		base = append(base, "hostname", hostname)
	}

	if tid := strings.TrimSpace(os.Getenv("TENANT_ID")); tid != "" {
		base = append(base, "tenant_id", tid)
	}

	return lg.With(base...)
}

// PacketInfo holds parsed network layer information from a raw packet.
type PacketInfo struct {
	Src             string
	Dst             string
	Protocol        string
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
}

// parseIPLayer decodes the IP layer from a raw packet payload.
// Returns the parsed packet, source/destination IPs, protocol number, and whether parsing succeeded.
func parseIPLayer(payload []byte) (gopacket.Packet, string, string, uint8, bool) { //nolint:ireturn
	switch payload[0] >> 4 {
	case 4:
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return nil, "", "", 0, false
		}

		ip := ipLayer.(*layers.IPv4) //nolint:forcetypeassert

		return packet, ip.SrcIP.String(), ip.DstIP.String(), uint8(ip.Protocol), true
	case 6:
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default)

		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			return nil, "", "", 0, false
		}

		ip6 := ip6Layer.(*layers.IPv6) //nolint:forcetypeassert

		return packet, ip6.SrcIP.String(), ip6.DstIP.String(), uint8(ip6.NextHeader), true
	default:
		return nil, "", "", 0, false
	}
}

// parsePacketInfo extracts network layer information from a raw packet payload.
// Supports both IPv4 and IPv6 packets.
func parsePacketInfo(payload []byte) PacketInfo {
	if len(payload) < minPacketSize {
		return PacketInfo{}
	}

	packet, srcIP, dstIP, protoNum, ok := parseIPLayer(payload)
	if !ok {
		return PacketInfo{}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP) //nolint:forcetypeassert

		return PacketInfo{
			Src:             fmt.Sprintf("%s:%d", srcIP, tcp.SrcPort),
			Dst:             fmt.Sprintf("%s:%d", dstIP, tcp.DstPort),
			Protocol:        "TCP",
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			SourcePort:      int(tcp.SrcPort),
			DestinationPort: int(tcp.DstPort),
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP) //nolint:forcetypeassert

		return PacketInfo{
			Src:             fmt.Sprintf("%s:%d", srcIP, udp.SrcPort),
			Dst:             fmt.Sprintf("%s:%d", dstIP, udp.DstPort),
			Protocol:        "UDP",
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			SourcePort:      int(udp.SrcPort),
			DestinationPort: int(udp.DstPort),
		}
	}

	return PacketInfo{
		Src:           srcIP,
		Dst:           dstIP,
		Protocol:      strconv.Itoa(int(protoNum)),
		SourceIP:      srcIP,
		DestinationIP: dstIP,
	}
}

// mapPrefixToAction maps nftables log prefix strings to action types.
func mapPrefixToAction(prefix string) string {
	pl := strings.ToLower(prefix)

	switch {
	case strings.Contains(pl, "redirect"):
		return filter.ActionRedirected
	case strings.Contains(pl, "block"):
		return "BLOCKED"
	case strings.Contains(pl, "allow"):
		return "ALLOWED"
	default:
		return ""
	}
}

// buildLogFields constructs a slice of structured log fields from packet information.
func buildLogFields(
	src, dst, proto, sourceIP, destinationIP, flowID string, sourcePort, destinationPort, payloadLen int,
) []any {
	fields := []any{
		"protocol", proto,
		"payload_len", payloadLen,
	}

	if src != "" {
		fields = append(fields, "src", src)
	}

	if dst != "" {
		fields = append(fields, "dst", dst)
	}

	if sourceIP != "" {
		fields = append(fields, "source_ip", sourceIP)
	}

	if sourcePort != 0 {
		fields = append(fields, "source_port", sourcePort)
	}

	if destinationIP != "" {
		fields = append(fields, "destination_ip", destinationIP)
	}

	if destinationPort != 0 {
		fields = append(fields, "destination_port", destinationPort)
	}

	if flowID != "" {
		fields = append(fields, "flow_id", flowID)
	}

	return fields
}

// processActionEvent logs nflog events, suppressing duplicate synthetic events when appropriate.
func processActionEvent(
	lg *slog.Logger,
	action, flowID string,
	pkt PacketInfo,
	payloadLen int,
) {
	// If we have a recent synthetic for this flow, suppress kernel nflog REDIRECTED to avoid duplicates
	if action == filter.ActionRedirected && flowID != "" && filter.IsSyntheticRecent(flowID) {
		return // handled, skip logging
	}

	fields := buildLogFields(
		pkt.Src, pkt.Dst, pkt.Protocol, pkt.SourceIP, pkt.DestinationIP,
		flowID, pkt.SourcePort, pkt.DestinationPort, payloadLen,
	)
	fields = append(fields, "action", action)

	// Level policy: REDIRECTED and ALLOWED at DEBUG, BLOCKED at INFO
	if action == filter.ActionRedirected || action == "ALLOWED" {
		lg.Debug("nflog.event", fields...)
	} else {
		lg.Info("nflog.event", fields...)
	}
}

// createNflogHook creates a callback function that processes each nflog packet and logs it.
func createNflogHook(lg *slog.Logger) func(nflog.Attribute) int {
	return func(attrs nflog.Attribute) int {
		prefix := ""
		if attrs.Prefix != nil {
			prefix = *attrs.Prefix
		}

		payloadLen := 0
		if attrs.Payload != nil {
			payloadLen = len(*attrs.Payload)
		}

		if payloadLen < minPacketSize {
			// Ignore tiny packets
			return 0
		}

		pkt := parsePacketInfo(*attrs.Payload)

		if pkt.Src == "" && pkt.Dst == "" {
			// Unsupported network layer
			return 0
		}

		action := mapPrefixToAction(prefix)

		// Compute flow id
		flowID := ""
		if pkt.SourceIP != "" && pkt.DestinationIP != "" {
			flowID = filter.FlowID(pkt.SourceIP, pkt.SourcePort, pkt.DestinationIP, pkt.DestinationPort, pkt.Protocol)
		}

		if action != "" {
			processActionEvent(lg, action, flowID, pkt, payloadLen)

			return 0
		}

		// Minimal debug for non-action packets (will include hostname/component from lg context)
		lg.Debug("nflog.packet",
			"prefix", prefix, "protocol", pkt.Protocol,
			"src", pkt.Src, "dst", pkt.Dst, "payload_len", payloadLen,
		)

		return 0
	}
}

// StreamNfLogWithLogger streams netfilter log events from group 0 using the provided logger until context is done.
func StreamNfLogWithLogger(ctx context.Context, lg *slog.Logger) error {
	dfltBuf, dfltQ := parseNflogConfig()
	lg = setupLogger(lg)

	config := nflog.Config{
		Group:    0,
		Copymode: nflog.CopyPacket,
		Bufsize:  dfltBuf,
		QThresh:  dfltQ,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		return fmt.Errorf("nflog open failed: %w", err)
	}

	defer func() { _ = nf.Close() }()

	// Error handler that silently continues on errors
	errFunc := func(_ error) int {
		return 0 // Return 0 to keep receiving messages
	}

	err = nf.RegisterWithErrorFunc(ctx, createNflogHook(lg), errFunc)
	if err != nil {
		return fmt.Errorf("register failed: %w", err)
	}

	// Block until context is cancelled
	<-ctx.Done()

	return nil
}
