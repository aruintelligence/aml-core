package main

// Policy threshold rule. Same rule and results as protocol/policyThreshold.js
// and independent/python/policy_threshold.py (vectors:
// conformance/policy-threshold/): threshold omitted -> 1; a positive
// (JavaScript-safe) integer -> itself; anything else -> "invalid_threshold"
// with a null threshold. An explicit invalid threshold is never replaced by 1.
//
//	aml-go-witness policy-threshold-conformance conformance/policy-threshold/vectors.json

import (
	"encoding/json"
	"fmt"
	"os"
)

const policyThresholdDefault = 1

func resolvePolicyThreshold(policy any) map[string]any {
	m, ok := policy.(map[string]any)
	if !ok {
		return map[string]any{"threshold": policyThresholdDefault, "error": nil}
	}
	value, present := m["threshold"]
	if !present {
		return map[string]any{"threshold": policyThresholdDefault, "error": nil}
	}
	if n, ok := jsSafeInteger(value); ok && n > 0 {
		return map[string]any{"threshold": n, "error": nil}
	}
	return map[string]any{"threshold": nil, "error": "invalid_threshold"}
}

func runPolicyThresholdConformance(path string) int {
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
		policy, err := strictJSON([]byte(cm["policy_json"].(string)))
		if err != nil {
			fmt.Fprintln(os.Stderr, cm["name"], err)
			return 2
		}
		results = append(results, map[string]any{"name": cm["name"], "result": resolvePolicyThreshold(policy)})
	}
	raw, _ := json.Marshal(map[string]any{"implementation": "go", "results": results})
	fmt.Println(string(raw))
	return 0
}
