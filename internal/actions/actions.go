// Package actions defines shared action and filter mode constants used across
// multiple internal packages without introducing import cycles.
package actions

// Action constants represent the outcome of a filter decision.
const (
	ActionAllowed    = "ALLOWED"
	ActionBlocked    = "BLOCKED"
	ActionRedirected = "REDIRECTED"

	ModeHTTPS = "https"
	ModeDNS   = "dns"
)
