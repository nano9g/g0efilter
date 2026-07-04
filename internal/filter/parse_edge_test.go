//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"testing"
)

type headCase struct {
	name     string
	request  string
	wantHost string
	wantErr  bool
}

func readHeadCases() []headCase {
	return []headCase{
		{
			"missing host header",
			"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
			"",
			false,
		},
		{
			"port stripped from host",
			"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
			"example.com",
			false,
		},
		{
			"host lowercased and trailing dot trimmed",
			"GET / HTTP/1.1\r\nHost: EXAMPLE.Com.\r\n\r\n",
			"example.com",
			false,
		},
		{
			"multiple host headers uses first",
			"GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n",
			"first.com",
			false,
		},
		{
			"truncated request line",
			"GET / HT",
			"",
			true,
		},
		{
			"headers never terminated",
			"GET / HTTP/1.1\r\nHost: example.com\r\n",
			"",
			true,
		},
		{
			"empty input",
			"",
			"",
			true,
		},
		{
			"garbage bytes",
			"\x16\x03\x01\x02\x00\x01",
			"",
			true,
		},
	}
}

func TestReadHeadWithTextprotoEdgeCases(t *testing.T) {
	t.Parallel()

	for _, tt := range readHeadCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			br := bufio.NewReader(strings.NewReader(tt.request))

			host, head, err := readHeadWithTextproto(br)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}

			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}

			// Consumed bytes must be preserved even on error so permissive modes can forward
			if len(tt.request) > 0 && err != nil && len(head) == 0 {
				t.Error("consumed bytes must be returned on parse error")
			}
		})
	}
}

func TestPeekClientHelloNonTLS(t *testing.T) {
	t.Parallel()

	// Plain HTTP bytes are not a ClientHello: error, but consumed bytes preserved
	input := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

	hello, buf, err := peekClientHello(strings.NewReader(input))
	if err == nil || hello != nil {
		t.Fatal("non-TLS data must not produce a ClientHello")
	}

	if buf == nil || buf.Len() == 0 {
		t.Error("consumed bytes must be preserved on error")
	}
}

func TestPeekClientHelloTruncated(t *testing.T) {
	t.Parallel()

	// A real ClientHello prefix, cut off mid-record
	full := buildClientHello(t, "example.com")

	hello, buf, err := peekClientHello(bytes.NewReader(full[:20]))
	if err == nil || hello != nil {
		t.Fatal("truncated ClientHello must error")
	}

	if buf == nil {
		t.Error("buffer must be returned on error")
	}
}

func TestPeekClientHelloWithSNI(t *testing.T) {
	t.Parallel()

	raw := buildClientHello(t, "sni.example.com")

	hello, buf, err := peekClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}

	if hello.ServerName != "sni.example.com" {
		t.Errorf("ServerName = %q, want sni.example.com", hello.ServerName)
	}

	if !bytes.Equal(buf.Bytes(), raw) {
		t.Error("peeked bytes must be preserved verbatim for splicing")
	}
}

func TestPeekClientHelloWithoutSNI(t *testing.T) {
	t.Parallel()

	raw := buildClientHello(t, "")

	hello, _, err := peekClientHello(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}

	if hello.ServerName != "" {
		t.Errorf("ServerName = %q, want empty for SNI-less hello", hello.ServerName)
	}
}

// buildClientHello captures the raw bytes a real TLS client sends first.
func buildClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	var sink bytes.Buffer

	conn := tls.Client(writeOnlyConn{w: &sink}, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // capturing handshake bytes only, no real connection
	})
	_ = conn.HandshakeContext(context.Background()) // fails after writing the ClientHello, which is all we need

	if sink.Len() == 0 {
		t.Fatal("no ClientHello captured")
	}

	return sink.Bytes()
}

type writeOnlyConn struct {
	roConn

	w *bytes.Buffer
}

func (c writeOnlyConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil {
		return n, fmt.Errorf("capture write: %w", err)
	}

	return n, nil
}

// Read fails immediately: the handshake ends right after the ClientHello is written.
func (c writeOnlyConn) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
