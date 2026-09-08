package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"
)

type result struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

func quoteString(s string) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return strings.TrimSpace(b.String()), nil
}

func canonical(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if x { return "true", nil }
		return "false", nil
	case string:
		return quoteString(x)
	case json.Number:
		return x.String(), nil
	case float64:
		b, err := json.Marshal(x)
		return string(b), err
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			c, err := canonical(item)
			if err != nil { return "", err }
			parts[i] = c
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x { keys = append(keys, k) }
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			q, err := quoteString(k)
			if err != nil { return "", err }
			c, err := canonical(x[k])
			if err != nil { return "", err }
			parts = append(parts, q+":"+c)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fmt.Errorf("unsupported canonical JSON type %T", v)
	}
}

func cloneWithout(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != key { out[k] = v }
	}
	return out
}

func sha256JSON(v any) (string, error) {
	c, err := canonical(v)
	if err != nil { return "", err }
	h := sha256.Sum256([]byte(c))
	return hex.EncodeToString(h[:]), nil
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func getString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func decodeB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func verifyRawP256(jwk map[string]any, message []byte, signature string) (bool, string) {
	if getString(jwk, "kty") != "EC" || getString(jwk, "crv") != "P-256" {
		return false, "AML_GO_KEY_UNSUPPORTED"
	}
	xb, err := decodeB64URL(getString(jwk, "x"))
	if err != nil { return false, "AML_GO_KEY_INVALID" }
	yb, err := decodeB64URL(getString(jwk, "y"))
	if err != nil { return false, "AML_GO_KEY_INVALID" }
	x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) { return false, "AML_GO_KEY_NOT_ON_CURVE" }
	sig, err := decodeB64URL(signature)
	if err != nil || len(sig) != 64 { return false, "AML_GO_SIGNATURE_ENCODING_UNSUPPORTED" }
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256(message)
	pub := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if !ecdsa.Verify(&pub, h[:], r, s) { return false, "AML_GO_SIGNATURE_INVALID" }
	return true, "AML_GO_SIGNATURE_VALID"
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func verifyBundle(bundle map[string]any, now time.Time) (bool, string) {
	if getString(bundle, "schema") != "aml-witness-bundle/1" {
		return false, "AML_GO_BUNDLE_INVALID"
	}
	integrity, ok := asMap(bundle["integrity"])
	if !ok || getString(integrity, "algorithm") != "SHA-256" {
		return false, "AML_GO_BUNDLE_ALGORITHM_UNSUPPORTED"
	}
	got, err := sha256JSON(cloneWithout(bundle, "integrity"))
	if err != nil || got != getString(integrity, "value") {
		return false, "AML_GO_BUNDLE_HASH_MISMATCH"
	}

	evidence, ok := asMap(bundle["evidence"])
	if !ok { return false, "AML_GO_EVIDENCE_INVALID" }
	receipt, ok := asMap(evidence["receipt"])
	if !ok { return false, "AML_GO_RECEIPT_INVALID" }
	receiptIntegrity, ok := asMap(receipt["integrity"])
	if !ok { return false, "AML_GO_RECEIPT_HASH_MISMATCH" }
	receiptHash, err := sha256JSON(cloneWithout(receipt, "integrity"))
	if err != nil || receiptHash != getString(receiptIntegrity, "value") {
		return false, "AML_GO_RECEIPT_HASH_MISMATCH"
	}
	evidenceIntegrity, ok := asMap(evidence["integrity"])
	if !ok { return false, "AML_GO_EVIDENCE_HASH_MISMATCH" }
	evidenceHash, err := sha256JSON(cloneWithout(evidence, "integrity"))
	if err != nil || evidenceHash != getString(evidenceIntegrity, "value") {
		return false, "AML_GO_EVIDENCE_HASH_MISMATCH"
	}

	challenge, ok := asMap(bundle["challenge"])
	if !ok || getString(challenge, "schema") != "aml-verification-challenge/1" {
		return false, "AML_GO_CHALLENGE_INVALID"
	}
	if len(getString(challenge, "nonce")) < 32 { return false, "AML_GO_CHALLENGE_NONCE_INVALID" }
	expires, err := parseTime(getString(challenge, "expires_at"))
	if err != nil { return false, "AML_GO_CHALLENGE_INVALID" }
	if now.After(expires) { return false, "AML_GO_CHALLENGE_EXPIRED" }

	att, ok := asMap(bundle["attestation"])
	if !ok || getString(att, "schema") != "aml-session-attestation/1" {
		return false, "AML_GO_ATTESTATION_INVALID"
	}
	if getString(att, "algorithm") != "ECDSA-P256-SHA256" {
		return false, "AML_GO_ATTESTATION_ALGORITHM_UNSUPPORTED"
	}
	if getString(att, "evidence_hash") != getString(evidenceIntegrity, "value") {
		return false, "AML_GO_ATTESTATION_EVIDENCE_MISMATCH"
	}
	if getString(att, "challenge_nonce") != getString(challenge, "nonce") {
		return false, "AML_GO_ATTESTATION_CHALLENGE_MISMATCH"
	}
	if getString(att, "challenge_expires_at") != getString(challenge, "expires_at") {
		return false, "AML_GO_ATTESTATION_CHALLENGE_EXPIRY_MISMATCH"
	}
	jwk, ok := asMap(att["session_public_key_jwk"])
	if !ok { return false, "AML_GO_KEY_INVALID" }
	fp, err := sha256JSON(jwk)
	if err != nil || fp != getString(att, "session_key_fingerprint") {
		return false, "AML_GO_KEY_FINGERPRINT_MISMATCH"
	}
	payload := cloneWithout(att, "signature")
	canon, err := canonical(payload)
	if err != nil { return false, "AML_GO_ATTESTATION_INVALID" }
	okSig, reason := verifyRawP256(jwk, []byte(canon), getString(att, "signature"))
	if !okSig { return false, reason }
	return true, "AML_GO_WITNESS_BUNDLE_VALID"
}

func readBundle(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var bundle map[string]any
	if err := dec.Decode(&bundle); err != nil { return nil, err }
	return bundle, nil
}

func main() {
	nowFlag := flag.String("now", "", "RFC3339 verification time for fixed vectors")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: go run . [--now RFC3339] bundle.json")
		os.Exit(2)
	}
	bundle, err := readBundle(flag.Arg(0))
	if err != nil { emit(result{false, "AML_GO_INPUT_INVALID"}, 2); return }
	now := time.Now().UTC()
	if *nowFlag != "" {
		now, err = parseTime(*nowFlag)
		if err != nil { emit(result{false, "AML_GO_NOW_INVALID"}, 2); return }
	}
	valid, reason := verifyBundle(bundle, now)
	code := 1
	if valid { code = 0 }
	emit(result{valid, reason}, code)
}

func emit(r result, code int) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil { panic(errors.New("unable to encode result")) }
	fmt.Println(string(data))
	os.Exit(code)
}
