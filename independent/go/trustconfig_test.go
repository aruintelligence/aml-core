package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// TestTrustConformanceVectors checks every step's `expect` subset from the
// shared vectors (test/trust-config-parity.test.js also compares full results
// with JavaScript and Python).
func TestTrustConformanceVectors(t *testing.T) {
	data, err := os.ReadFile("../../conformance/trust-config/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.(map[string]any)["cases"].([]any) {
		cm := c.(map[string]any)
		steps, err := runCase(cm, t.TempDir())
		if err != nil {
			t.Fatalf("%v: %v", cm["name"], err)
		}
		for i, s := range cm["steps"].([]any) {
			raw, _ := json.Marshal(steps[i])
			var got map[string]any
			_ = json.Unmarshal(raw, &got)
			expRaw, _ := json.Marshal(s.(map[string]any)["expect"])
			var exp map[string]any
			_ = json.Unmarshal(expRaw, &exp)
			for k, want := range exp {
				if !reflect.DeepEqual(got[k], want) {
					t.Errorf("%v[%d].%s = %v, want %v", cm["name"], i, k, got[k], want)
				}
			}
		}
	}
}

func TestTrustSignatureEncodingStrict(t *testing.T) {
	if sigRe.MatchString("AAAA") {
		t.Fatal("short signature accepted")
	}
	if _, ok := isoMs("2026-02-30T00:00:00Z"); ok {
		t.Fatal("calendar-impossible date accepted")
	}
}
