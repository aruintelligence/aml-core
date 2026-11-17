package main

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// decodeB64URL must accept exactly one spelling: canonical unpadded base64url
// (the same rule as independent/python/verify_witness.py b64url_decode).
func TestDecodeB64URLCanonicalOnly(t *testing.T) {
	for n := 1; n <= 96; n++ {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		s := base64.RawURLEncoding.EncodeToString(b)
		got, err := decodeB64URL(s)
		if err != nil || string(got) != string(b) {
			t.Fatalf("canonical length %d refused: %v", n, err)
		}
	}
	x := make([]byte, 32)
	if _, err := rand.Read(x); err != nil {
		t.Fatal(err)
	}
	s := base64.RawURLEncoding.EncodeToString(x) // 43 chars, 2 unused bits
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	flipped := s[:42] + string(alphabet[strings.IndexByte(alphabet, s[42])+1])
	bad := map[string]string{
		"noncanonical_trailing_bits": flipped,
		"embedded_newline":           s[:20] + "\n" + s[20:],
		"embedded_cr":                s[:20] + "\r" + s[20:],
		"trailing_newline":           s + "\n",
		"padded":                     s + "=",
		"standard_alphabet":          strings.NewReplacer("-", "+", "_", "/").Replace(s) + "+",
		"trailing_junk":              s + "!",
		"embedded_space":             s[:20] + " " + s[20:],
		"empty":                      "",
	}
	for name, v := range bad {
		if _, err := decodeB64URL(v); err == nil {
			t.Errorf("%s accepted: %q", name, v)
		}
	}
}
