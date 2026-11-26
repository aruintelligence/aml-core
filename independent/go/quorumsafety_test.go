package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// TestQuorumSafetyVectors: every k-of-n vector (exhaustive to n = 16, boundary
// sizes to 64, malformed inputs) matches the committed expectation.
func TestQuorumSafetyVectors(t *testing.T) {
	data, err := os.ReadFile("../../conformance/quorum-safety/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for i, c := range v.(map[string]any)["cases"].([]any) {
		cm := c.(map[string]any)
		got := evaluateQuorumSafety(cm["threshold"], cm["witness_count"])
		for k, want := range cm["expect"].(map[string]any) {
			g, _ := json.Marshal(got[k])
			w, _ := json.Marshal(want)
			var gv, wv any
			_ = json.Unmarshal(g, &gv)
			_ = json.Unmarshal(w, &wv)
			if !reflect.DeepEqual(gv, wv) {
				t.Errorf("case %d (%v-of-%v).%s = %s, want %s", i, cm["threshold"], cm["witness_count"], k, g, w)
			}
		}
		if got["valid"] == true {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("no accepted configuration in vectors")
	}
	for _, unsafe := range [][2]int{{4, 7}, {2, 3}, {1, 1}, {2, 4}} {
		got := evaluateQuorumSafety(json.Number(itoa(unsafe[0])), json.Number(itoa(unsafe[1])))
		if got["valid"] != false {
			t.Errorf("%d-of-%d must be refused", unsafe[0], unsafe[1])
		}
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }
