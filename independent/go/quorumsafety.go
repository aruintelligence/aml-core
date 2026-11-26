package main

// k-of-n witness quorum safety rule. Same rule, reasons and fields as
// protocol/quorumSafety.js and independent/python/quorum_safety.py (vectors:
// conformance/quorum-safety/): accepted only when 1 <= k <= n <= 64 are
// (JavaScript-safe) integers and safety_fault_tolerance = 2k - n - 1 >= 1.
//
//	aml-go-witness quorum-safety-conformance conformance/quorum-safety/vectors.json

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
)

const maxQuorumWitnesses = 64

// jsSafeInteger mirrors Number.isSafeInteger on a decoded JSON value.
func jsSafeInteger(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Abs(f) > (1<<53)-1 {
		return 0, false
	}
	return int64(f), true
}

func evaluateQuorumSafety(threshold, witnessCount any) map[string]any {
	out := map[string]any{"threshold": threshold, "witness_count": witnessCount}
	result := func(valid bool, reason any) map[string]any {
		out["valid"] = valid
		out["reason"] = reason
		return out
	}
	n, ok := jsSafeInteger(witnessCount)
	if !ok {
		return result(false, "witness_count_not_integer")
	}
	k, ok := jsSafeInteger(threshold)
	if !ok {
		return result(false, "threshold_not_integer")
	}
	if n < 1 || n > maxQuorumWitnesses {
		return result(false, "witness_count_out_of_range")
	}
	if k < 1 || k > n {
		return result(false, "threshold_out_of_range")
	}
	out["quorum_intersection"] = 2*k - n
	out["safety_fault_tolerance"] = 2*k - n - 1
	out["liveness_fault_tolerance"] = n - k
	if 2*k <= n {
		return result(false, "quorums_may_not_intersect")
	}
	if 2*k-n-1 < 1 {
		return result(false, "zero_fault_tolerance")
	}
	return result(true, nil)
}

func runQuorumSafetyConformance(path string) int {
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
		got := evaluateQuorumSafety(cm["threshold"], cm["witness_count"])
		picked := map[string]any{}
		for k := range cm["expect"].(map[string]any) {
			picked[k] = got[k]
		}
		results = append(results, picked)
	}
	raw, _ := json.Marshal(map[string]any{"implementation": "go", "results": results})
	fmt.Println(string(raw))
	return 0
}
