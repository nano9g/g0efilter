// Package actions defines shared action and filter mode constants used across
// multiple internal packages without introducing import cycles.
package actions

const (
	// ActionAllowed is the action string for allowed connections.
	ActionAllowed = "ALLOWED"

	// ActionBlocked is the action string for blocked connections.
	ActionBlocked = "BLOCKED"

	// ActionRedirected is logged when traffic is redirected.
	ActionRedirected = "REDIRECTED"

	// ModeHTTPS is the HTTPS-based filtering mode.
	ModeHTTPS = "https"

	// ModeDNS is the DNS-based filtering mode.
	ModeDNS = "dns"
)
