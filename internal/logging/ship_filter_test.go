//nolint:testpackage // Need access to internal implementation details
package logging

import "testing"

func TestShouldShipToDashboard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		act   string
		attrs map[string]any
		want  bool
	}{
		{"blocked ships", "BLOCKED", map[string]any{}, true},
		{"allowed ships", "ALLOWED", map[string]any{}, true},
		{"audit ships", "AUDIT", map[string]any{}, true},
		{"redirected does not ship", "REDIRECTED", map[string]any{}, false},
		{"empty action does not ship", "", map[string]any{}, false},
		{"nflog allowed suppressed", "ALLOWED", map[string]any{"component": "nflog"}, false},
		{"nflog audit still ships", "AUDIT", map[string]any{"component": "nflog"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := shouldShipToDashboard(tt.act, tt.attrs); got != tt.want {
				t.Errorf("shouldShipToDashboard(%q, %v) = %v, want %v", tt.act, tt.attrs, got, tt.want)
			}
		})
	}
}
