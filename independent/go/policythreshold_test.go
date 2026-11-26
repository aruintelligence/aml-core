package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// TestPolicyThresholdVectors: every policy-threshold vector resolves exactly
// as committed; an explicit invalid threshold is an error, never 1.
func TestPolicyThresholdVectors(t *testing.T) {
	data, err := os.ReadFile("../../conformance/policy-threshold/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.(map[string]any)["cases"].([]any) {
		cm := c.(map[string]any)
		policy, err := strictJSON([]byte(cm["policy_json"].(string)))
		if err != nil {
			t.Fatalf("%v: %v", cm["name"], err)
		}
		got, _ := json.Marshal(resolvePolicyThreshold(policy))
		want, _ := json.Marshal(cm["expect"])
		var g, w any
		_ = json.Unmarshal(got, &g)
		_ = json.Unmarshal(want, &w)
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%v: got %s, want %s", cm["name"], got, want)
		}
	}
}
