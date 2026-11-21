package mqtt

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

// A key/value payload rides the req_id envelope when JSON carries it byte for
// byte, and goes raw when it would not (invalid UTF-8, NUL).
func TestCLIRequestFields_EnvelopeOnlyWhenExact(t *testing.T) {
	for name, tc := range map[string]struct {
		payload  []byte
		envelope bool
	}{
		"pem":          {[]byte("client_cert\n-----BEGIN CERTIFICATE-----\nAB<&>\n"), true},
		"invalid utf8": {[]byte("web.password\n\xff\xfe"), false},
		"nul":          {[]byte("web.password\na\x00b"), false},
	} {
		t.Run(name, func(t *testing.T) {
			var sent []byte
			c := &Client{c: &answerBroker{answer: func(_ string, p []byte) { sent = p }}}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			_, _ = c.CLIRequestFields(ctx, "thesada/t/d", "secret.set", tc.payload)

			var env cliEnvelope
			wrapped := json.Unmarshal(sent, &env) == nil && env.ReqID != ""
			if wrapped != tc.envelope {
				t.Fatalf("enveloped = %v, want %v (sent %q)", wrapped, tc.envelope, sent)
			}
			if wrapped && env.Args != string(tc.payload) {
				t.Fatalf("args = %q, want the payload unchanged", env.Args)
			}
			if !wrapped && !bytes.Equal(sent, tc.payload) {
				t.Fatalf("raw publish = %q, want the payload unchanged", sent)
			}
		})
	}
}
