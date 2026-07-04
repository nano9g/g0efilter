// Package actions defines shared action and filter mode constants used across
// multiple internal packages without introducing import cycles.
package actions

// Action constants represent the outcome of a filter decision.
const (
	ActionAllowed    = "ALLOWED"
	ActionBlocked    = "BLOCKED"
	ActionRedirected = "REDIRECTED"
	// ActionAudit marks traffic that would have been blocked but was allowed
	// because audit (dry-run) enforcement is active.
	ActionAudit = "AUDIT"

	ModeHTTPS = "https"
	ModeDNS   = "dns"
	// ModeDNSStrict is DNS mode plus connection-time enforcement: resolved IPs of
	// allowed domains are pushed into a kernel timeout set and everything else drops.
	ModeDNSStrict = "dns-strict"
)
