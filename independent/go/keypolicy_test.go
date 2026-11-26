package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// TestKeyPolicyVectors: every capability-token / threshold-authorization
// vector (Ed25519-only rule) is decided exactly as the committed expectation
// (test/key-policy.test.js also compares full results with JS and Python).
func TestKeyPolicyVectors(t *testing.T) {
	data, err := os.ReadFile("../../conformance/key-policy/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, c := range v.(map[string]any)["cases"].([]any) {
		cm := c.(map[string]any)
		got, err := keyPolicyDecide(cm["kind"].(string), cm["artifact"])
		if err != nil {
			t.Fatal(err)
		}
		gotRaw, _ := json.Marshal(got)
		expRaw, _ := json.Marshal(cm["expect"])
		var g, e map[string]any
		_ = json.Unmarshal(gotRaw, &g)
		_ = json.Unmarshal(expRaw, &e)
		if !reflect.DeepEqual(g, e) {
			t.Errorf("%v: got %s, want %s", cm["name"], gotRaw, expRaw)
		}
		if g["reason"] == "key_type_not_ed25519" {
			refused++
		}
	}
	if refused < 10 {
		t.Fatalf("expected at least 10 non-Ed25519 refusals, got %d", refused)
	}
}
