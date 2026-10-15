package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, 8-byte time, the ASCII secret.
func TestRFC6238SHA1(t *testing.T) {
	key := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tc := range cases {
		at := time.Unix(tc.unix, 0)
		if got := Code(key, at); got != tc.code {
			t.Errorf("unix %d: got %s want %s", tc.unix, got, tc.code)
		}
		if !Verify(key, tc.code, at) {
			t.Errorf("unix %d: verify rejected %s", tc.unix, tc.code)
		}
	}
}

func TestVerifyAcceptsOneStepSkew(t *testing.T) {
	key := []byte("12345678901234567890")
	at := time.Unix(59, 0)
	next := Code(key, at.Add(step))
	if !Verify(key, next, at) {
		t.Fatal("next step was rejected")
	}
	far := Code(key, at.Add(2*step))
	if Verify(key, far, at) {
		t.Fatal("two steps ahead was accepted")
	}
}

func TestNewKey_DecodesToTheSameKeyAndVerifies(t *testing.T) {
	raw, encoded, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatal("decode mismatch")
	}
	at := time.Unix(1_700_000_000, 0)
	if !Verify(raw, Code(raw, at), at) {
		t.Fatal("fresh key did not verify")
	}
}

func TestCheck_CorruptSecretIsError(t *testing.T) {
	_, err := Check("!!!", "000000", time.Unix(0, 0))
	if err == nil {
		t.Fatal("corrupt secret was treated as a rejected code")
	}
	if got := err.Error(); got == "illegal base32 data at input byte 0" || !strings.HasPrefix(got, "totp: decode secret:") {
		t.Fatalf("decode error = %q, want one totp: prefix", got)
	}
}

func TestCheck_WrongCodeIsFalse(t *testing.T) {
	raw, encoded, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(59, 0)
	ok, err := Check(encoded, "000000", at)
	if err != nil {
		t.Fatal(err)
	}
	if Code(raw, at) != "000000" && ok {
		t.Fatal("wrong code was accepted")
	}
	ok, err = Check(encoded, Code(raw, at), at)
	if err != nil || !ok {
		t.Fatalf("good code ok=%v err=%v", ok, err)
	}
}
