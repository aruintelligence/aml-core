package main

// Ed25519-only key policy for capability tokens and threshold authorizations.
// Same rule, reasons and order of checks as protocol/keyPolicy.js,
// runtime/capabilityToken.js (verifyCapabilityToken),
// runtime/thresholdAuthorization.js (verifyThresholdAuthorization) and
// independent/python/key_policy.py; shared vectors in
// conformance/key-policy/vectors.json. Signature layer only: never an
// authorization decision.
//
//	aml-go-witness key-policy-conformance conformance/key-policy/vectors.json

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	capabilityTokenType           = "aml-capability-token/1"
	thresholdAuthorizationVersion = "1.1"
	maxSignatureBytes             = 512
)

var (
	pemBlockRe       = regexp.MustCompile(`^-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*$`)
	standardBase64Re = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
	// SPKI algorithm OIDs -> Node.js asymmetricKeyType.
	spkiKeyTypes = map[string]string{
		"1.3.101.112":           "ed25519",
		"1.3.101.113":           "ed448",
		"1.3.101.110":           "x25519",
		"1.3.101.111":           "x448",
		"1.2.840.10045.2.1":     "ec",
		"1.2.840.113549.1.1.1":  "rsa",
		"1.2.840.113549.1.1.10": "rsa-pss",
		"1.2.840.10040.4.1":     "dsa",
	}
)

type spkiAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type spki struct {
	Algorithm spkiAlgorithm
	PublicKey asn1.BitString
}

type parsedKey struct {
	keyType string
	der     []byte
	raw     []byte
}

// parsePublicKey returns nil when the value is not a parseable SPKI public key.
func parsePublicKey(v any) *parsedKey {
	pem, ok := v.(string)
	if !ok {
		return nil
	}
	m := pemBlockRe.FindStringSubmatch(pem)
	if m == nil {
		return nil
	}
	der, err := base64.StdEncoding.Strict().DecodeString(strings.Join(strings.Fields(m[1]), ""))
	if err != nil {
		return nil
	}
	var key spki
	rest, err := asn1.Unmarshal(der, &key)
	if err != nil || len(rest) != 0 || key.PublicKey.BitLength%8 != 0 {
		return nil
	}
	keyType, known := spkiKeyTypes[key.Algorithm.Algorithm.String()]
	if !known {
		return nil
	}
	if keyType == "ed25519" && (len(key.Algorithm.Parameters.FullBytes) != 0 || len(key.PublicKey.Bytes) != ed25519.PublicKeySize) {
		return nil
	}
	return &parsedKey{keyType: keyType, der: der, raw: key.PublicKey.Bytes}
}

func decodeSignatureBase64(v any) []byte {
	s, ok := v.(string)
	if !ok || s == "" || len(s) > 4*((maxSignatureBytes+2)/3) || !standardBase64Re.MatchString(s) {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 || len(raw) > maxSignatureBytes || base64.StdEncoding.EncodeToString(raw) != s {
		return nil
	}
	return raw
}

func fingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func verifyCapabilityTokenPolicy(v any) map[string]any {
	deny := func(reason string) map[string]any { return map[string]any{"valid": false, "reason": reason} }
	token, ok := v.(map[string]any)
	if !ok || token["type"] != capabilityTokenType {
		return deny("invalid_type")
	}
	body := map[string]any{}
	for k, val := range token {
		if k != "public_key_pem" && k != "public_key_fingerprint" && k != "signature_base64" {
			body[k] = val
		}
	}
	key := parsePublicKey(token["public_key_pem"])
	if key == nil {
		return deny("signature_invalid")
	}
	if key.keyType != "ed25519" {
		return deny("key_type_not_ed25519")
	}
	if fp, _ := token["public_key_fingerprint"].(string); fp != fingerprintDER(key.der) {
		return deny("fingerprint_mismatch")
	}
	signature := decodeSignatureBase64(token["signature_base64"])
	message, err := canonical(body)
	if err != nil || signature == nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key.raw), []byte(message), signature) {
		return deny("signature_invalid")
	}
	return map[string]any{"valid": true, "reason": nil}
}

// jsInteger mirrors Number.isInteger on a decoded JSON number.
func jsInteger(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Abs(f) > 1<<62 {
		return 0, false
	}
	return int64(f), true
}

func verifyThresholdAuthorizationPolicy(v any) map[string]any {
	deny := func(reason string, rejected []string, validSigs int) map[string]any {
		if rejected == nil {
			rejected = []string{}
		}
		return map[string]any{"valid": false, "reason": reason, "valid_signatures": validSigs, "rejected_key_types": rejected}
	}
	auth, ok := v.(map[string]any)
	if !ok {
		return deny("invalid_threshold", nil, 0)
	}
	threshold, ok := jsInteger(auth["threshold"])
	if !ok || threshold < 1 {
		return deny("invalid_threshold", nil, 0)
	}
	if auth["version"] != thresholdAuthorizationVersion {
		return deny("legacy_threshold_unbound", nil, 0)
	}
	sigs, ok := auth["signatures"].([]any)
	if !ok {
		return deny("invalid_signatures", nil, 0)
	}
	message, err := canonical(map[string]any{"context": auth["type"], "version": auth["version"],
		"threshold": json.Number(strconv.FormatInt(threshold, 10)), "payload": auth["payload"]})
	if err != nil {
		return deny("invalid_payload", nil, 0)
	}
	rejectedSet := map[string]bool{}
	keys := make([]*parsedKey, len(sigs))
	for i, item := range sigs {
		if m, ok := item.(map[string]any); ok {
			keys[i] = parsePublicKey(m["public_key_pem"])
			if keys[i] != nil && keys[i].keyType != "ed25519" {
				rejectedSet[keys[i].keyType] = true
			}
		}
	}
	if len(rejectedSet) > 0 {
		rejected := make([]string, 0, len(rejectedSet))
		for k := range rejectedSet {
			rejected = append(rejected, k)
		}
		sort.Strings(rejected)
		return deny("key_type_not_ed25519", rejected, 0)
	}
	seen := map[string]bool{}
	valid := 0
	for i, item := range sigs {
		key := keys[i]
		if key == nil {
			continue
		}
		m := item.(map[string]any)
		fp := fingerprintDER(key.der)
		if claimed, _ := m["key_fingerprint"].(string); claimed != fp || seen[fp] {
			continue
		}
		signature := decodeSignatureBase64(m["signature_base64"])
		if signature != nil && len(signature) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(key.raw), []byte(message), signature) {
			seen[fp] = true
			valid++
		}
	}
	if int64(valid) >= threshold {
		return map[string]any{"valid": true, "reason": nil, "valid_signatures": valid, "rejected_key_types": []string{}}
	}
	return deny("threshold_not_met", nil, valid)
}

func keyPolicyDecide(kind string, artifact any) (map[string]any, error) {
	switch kind {
	case "capability-token":
		return verifyCapabilityTokenPolicy(artifact), nil
	case "threshold-authorization":
		return verifyThresholdAuthorizationPolicy(artifact), nil
	}
	return nil, fmt.Errorf("unknown vector kind %q", kind)
}

func runKeyPolicyConformance(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	v, err := strictJSON(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	results := []any{}
	for _, c := range v.(map[string]any)["cases"].([]any) {
		cm := c.(map[string]any)
		kind, _ := cm["kind"].(string)
		decision, err := keyPolicyDecide(kind, cm["artifact"])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		results = append(results, map[string]any{"name": cm["name"], "decision": decision})
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]any{"implementation": "go", "results": results})
	fmt.Print(out.String())
	return 0
}
