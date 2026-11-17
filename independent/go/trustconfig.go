package main

// Signed, versioned trust config and durable single use (Go standard library
// only). Same semantics, check names and reasons as runtime/trustConfig.js;
// conformance/trust-config/vectors.json holds the shared cases that the
// JavaScript, Python and Go implementations must agree on.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	trustConfigType      = "aml-trust-config/1"
	trustAnchorType      = "aml-trust-anchor/1"
	trustStateRecordType = "aml-trust-state-record/1"
	systemTrustStateDir  = "/etc/aml/trust"
	maxTrustKeys         = 64
	maxStateRecords      = 100000
	maxSafeInteger       = 9007199254740991
	exitAuthorized       = 0
)

var (
	trustRoles    = []string{"receipt", "policy-pack", "build-attestation", "brand-authorization", "capability-issuer"}
	hex64Re       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	isoRe         = regexp.MustCompile(`^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,3}))?Z$`)
	pemRe         = regexp.MustCompile(`^-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/]{64}\n)*[A-Za-z0-9+/]{1,63}={0,2}\n-----END PUBLIC KEY-----\n?$`)
	sigRe         = regexp.MustCompile(`^[A-Za-z0-9+/]{85}[AQgw]==$`)
	recordFileRe  = regexp.MustCompile(`^v(\d{12})\.json$`)
	spkiPrefix, _ = hex.DecodeString("302a300506032b6570032100")
	bodyKeys      = []string{"expires_at", "issued_at", "policy_sha256", "profile_sha256", "registry_sha256", "require_single_use",
		"revoked_keys", "root", "trusted_keys", "type", "version"}
	trustChecks = []string{"anchor_present", "state_readable", "envelope_well_formed", "root_threshold_met", "new_root_threshold_met",
		"not_rolled_back", "no_version_fork", "caller_time_absent", "trusted_time", "issued_not_in_future", "not_expired", "state_persisted"}
)

// ---------- strict JSON (duplicate keys rejected, numbers kept) ----------
func strictJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := strictValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

func strictValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				if _, dup := m[k]; dup {
					return nil, errors.New("duplicate_key")
				}
				v, err := strictValue(dec)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			_, err := dec.Token()
			return m, err
		}
		if t == '[' {
			a := []any{}
			for dec.More() {
				v, err := strictValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := dec.Token()
			return a, err
		}
		return nil, errors.New("unexpected delimiter")
	default:
		return tok, nil
	}
}

func readJSONLoose(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	err = dec.Decode(&v)
	return v, err
}

// asInt mirrors Number.isSafeInteger on a parsed JSON number.
func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Abs(f) > maxSafeInteger {
		return 0, false
	}
	return int64(f), true
}

func isoMs(v any) (int64, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	m := isoRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n := make([]int, 6)
	for i := 0; i < 6; i++ {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	frac := 0
	if m[7] != "" {
		frac, _ = strconv.Atoi((m[7] + "00")[:3])
	}
	if n[0] < 1970 {
		return 0, false
	}
	t := time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4], n[5], 0, time.UTC)
	if t.Year() != n[0] || int(t.Month()) != n[1] || t.Day() != n[2] || t.Hour() != n[3] || t.Minute() != n[4] || t.Second() != n[5] {
		return 0, false
	}
	return t.UnixMilli() + int64(frac), true
}

func isoFromMs(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

func isHex64(v any) bool {
	s, ok := v.(string)
	return ok && hex64Re.MatchString(s)
}

func uniqueHexList(v any, min int) ([]string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) < min || len(a) > maxTrustKeys {
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if !isHex64(x) || seen[x.(string)] {
			return nil, false
		}
		seen[x.(string)] = true
		out = append(out, x.(string))
	}
	return out, true
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type trustRoot struct {
	Keyids    []string `json:"keyids"`
	Threshold int64    `json:"threshold"`
}

func parseRoot(v any) (trustRoot, bool) {
	m, ok := v.(map[string]any)
	if !ok || !sameStrings(sortedKeys(m), []string{"keyids", "threshold"}) {
		return trustRoot{}, false
	}
	ids, ok := uniqueHexList(m["keyids"], 1)
	if !ok {
		return trustRoot{}, false
	}
	t, ok := asInt(m["threshold"])
	if !ok || t < 1 || t > int64(len(ids)) {
		return trustRoot{}, false
	}
	return trustRoot{ids, t}, true
}

func (r trustRoot) canonical() map[string]any {
	ids := make([]any, len(r.Keyids))
	for i, k := range r.Keyids {
		ids[i] = k
	}
	return map[string]any{"keyids": ids, "threshold": json.Number(strconv.FormatInt(r.Threshold, 10))}
}

func (r trustRoot) has(id string) bool {
	for _, k := range r.Keyids {
		if k == id {
			return true
		}
	}
	return false
}

type trustedKey struct {
	Keyid string   `json:"keyid"`
	Roles []string `json:"roles"`
}

type trustBody struct {
	raw       map[string]any
	version   int64
	issuedMs  int64
	expiresMs int64
	root      trustRoot
	keys      []trustedKey
	revoked   []string
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// validateBody mirrors validateTrustConfigBody (same error names, same order).
func validateBody(v any) (*trustBody, string) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, "body_not_object"
	}
	if !sameStrings(sortedKeys(m), bodyKeys) {
		return nil, "body_fields"
	}
	if s, ok := m["type"].(string); !ok || s != trustConfigType {
		return nil, "type"
	}
	version, ok := asInt(m["version"])
	if !ok || version < 1 || version > 999999999999 {
		return nil, "version"
	}
	issued, ok1 := isoMs(m["issued_at"])
	expires, ok2 := isoMs(m["expires_at"])
	if !ok1 || !ok2 || expires <= issued {
		return nil, "time_window"
	}
	root, ok := parseRoot(m["root"])
	if !ok {
		return nil, "root"
	}
	list, ok := m["trusted_keys"].([]any)
	if !ok || len(list) > maxTrustKeys {
		return nil, "trusted_keys"
	}
	seen := map[string]bool{}
	keys := []trustedKey{}
	for _, e := range list {
		em, ok := e.(map[string]any)
		if !ok || !sameStrings(sortedKeys(em), []string{"keyid", "roles"}) {
			return nil, "trusted_keys"
		}
		id, ok := em["keyid"].(string)
		if !ok || !hex64Re.MatchString(id) || seen[id] {
			return nil, "trusted_keys"
		}
		seen[id] = true
		roles, ok := em["roles"].([]any)
		if !ok || len(roles) == 0 {
			return nil, "trusted_key_roles"
		}
		rs := []string{}
		rseen := map[string]bool{}
		for _, r := range roles {
			s, ok := r.(string)
			if !ok || rseen[s] || !contains(trustRoles, s) {
				return nil, "trusted_key_roles"
			}
			rseen[s] = true
			rs = append(rs, s)
		}
		keys = append(keys, trustedKey{id, rs})
	}
	revoked, ok := uniqueHexList(m["revoked_keys"], 0)
	if !ok {
		return nil, "revoked_keys"
	}
	for _, name := range []string{"policy_sha256", "registry_sha256", "profile_sha256"} {
		if m[name] != nil && !isHex64(m[name]) {
			return nil, "digests"
		}
	}
	if _, ok := m["require_single_use"].(bool); !ok {
		return nil, "require_single_use"
	}
	norm := map[string]any{}
	for k, val := range m {
		norm[k] = val
	}
	norm["version"] = json.Number(strconv.FormatInt(version, 10))
	norm["root"] = root.canonical()
	return &trustBody{norm, version, issued, expires, root, keys, revoked}, ""
}

func keyFingerprint(pem string) (string, ed25519.PublicKey, error) {
	if !pemRe.MatchString(pem) {
		return "", nil, errors.New("AML_TRUST_KEY_PEM_INVALID")
	}
	var body strings.Builder
	for _, line := range strings.Split(pem, "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			body.WriteString(line)
		}
	}
	der, err := base64.StdEncoding.Strict().DecodeString(body.String())
	if err != nil {
		return "", nil, errors.New("AML_TRUST_KEY_PEM_INVALID")
	}
	if len(der) != 44 || !bytes.Equal(der[:12], spkiPrefix) {
		return "", nil, errors.New("AML_TRUST_KEY_NOT_ED25519")
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), ed25519.PublicKey(der[12:]), nil
}

func countThreshold(sigs []any, message []byte, root trustRoot) int64 {
	good := map[string]bool{}
	for _, s := range sigs {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		pem, ok1 := m["public_key_pem"].(string)
		sig64, ok2 := m["signature_base64"].(string)
		if !ok1 || !ok2 || !sigRe.MatchString(sig64) {
			continue
		}
		id, pub, err := keyFingerprint(pem)
		if err != nil {
			continue
		}
		claimed, _ := m["keyid"].(string)
		if id != claimed || !root.has(id) || good[id] {
			continue
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(sig64)
		if err == nil && ed25519.Verify(pub, message, sig) {
			good[id] = true
		}
	}
	return int64(len(good))
}

// ---------- durable state ----------
func fsyncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

func createExclusiveDurable(path string, contents []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		return true, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return true, err
	}
	if err := f.Close(); err != nil {
		return true, err
	}
	fsyncDir(filepath.Dir(path))
	return true, nil
}

func enrolled(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "anchor.json"))
	return err == nil
}

type stateRecord struct {
	Type         string    `json:"type"`
	Version      int64     `json:"version"`
	ConfigSha256 string    `json:"config_sha256"`
	Root         trustRoot `json:"root"`
	RevokedKeys  []string  `json:"revoked_keys"`
	IssuedAt     string    `json:"issued_at"`
	AcceptedAt   string    `json:"accepted_at"`
}

type trustState struct {
	records  []stateRecord
	latest   *stateRecord
	root     trustRoot
	revoked  map[string]bool
	floor    int64
	hasFloor bool
}

func readState(dir string) (*trustState, error) {
	av, err := readJSONLoose(filepath.Join(dir, "anchor.json"))
	if err != nil {
		return nil, err
	}
	am, ok := av.(map[string]any)
	if !ok || am["type"] != trustAnchorType {
		return nil, errors.New("AML_TRUST_ANCHOR_INVALID")
	}
	anchorRoot, ok := parseRoot(am["root"])
	if !ok {
		return nil, errors.New("AML_TRUST_ANCHOR_INVALID")
	}
	versions := filepath.Join(dir, "versions")
	entries, err := os.ReadDir(versions)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(entries) > maxStateRecords {
		return nil, errors.New("AML_TRUST_STATE_TOO_LARGE")
	}
	st := &trustState{revoked: map[string]bool{}}
	for _, e := range entries {
		name := e.Name()
		match := recordFileRe.FindStringSubmatch(name)
		if match == nil {
			if strings.HasPrefix(name, ".") {
				continue
			}
			return nil, errors.New("AML_TRUST_STATE_UNEXPECTED_FILE")
		}
		rv, err := readJSONLoose(filepath.Join(versions, name))
		if err != nil {
			return nil, err
		}
		rm, ok := rv.(map[string]any)
		want, _ := strconv.ParseInt(match[1], 10, 64)
		if !ok || rm["type"] != trustStateRecordType {
			return nil, errors.New("AML_TRUST_STATE_RECORD_INVALID")
		}
		ver, ok1 := asInt(rm["version"])
		root, ok2 := parseRoot(rm["root"])
		revoked, ok3 := uniqueHexList(rm["revoked_keys"], 0)
		issued, ok4 := isoMs(rm["issued_at"])
		accepted, ok5 := isoMs(rm["accepted_at"])
		sha, _ := rm["config_sha256"].(string)
		if !ok1 || ver != want || !hex64Re.MatchString(sha) || !ok2 || !ok3 || !ok4 || !ok5 {
			return nil, errors.New("AML_TRUST_STATE_RECORD_INVALID")
		}
		st.records = append(st.records, stateRecord{trustStateRecordType, ver, sha, root, revoked, rm["issued_at"].(string), rm["accepted_at"].(string)})
		for _, k := range revoked {
			st.revoked[k] = true
		}
		for _, t := range []int64{issued, accepted} {
			if !st.hasFloor || t > st.floor {
				st.floor, st.hasFloor = t, true
			}
		}
	}
	sort.Slice(st.records, func(i, j int) bool { return st.records[i].Version < st.records[j].Version })
	st.root = anchorRoot
	if len(st.records) > 0 {
		st.latest = &st.records[len(st.records)-1]
		st.root = st.latest.Root
	}
	return st, nil
}

func initTrustState(dir string, threshold int64, keyids []string) error {
	ids := make([]any, len(keyids))
	for i, k := range keyids {
		ids[i] = k
	}
	root, ok := parseRoot(map[string]any{"keyids": ids, "threshold": json.Number(strconv.FormatInt(threshold, 10))})
	if !ok {
		return errors.New("AML_TRUST_ANCHOR_INVALID_ROOT")
	}
	if err := os.MkdirAll(filepath.Join(dir, "versions"), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(map[string]any{"type": trustAnchorType, "root": root}, "", "  ")
	created, err := createExclusiveDurable(filepath.Join(dir, "anchor.json"), append(data, '\n'))
	if err != nil {
		return err
	}
	if !created {
		return errors.New("AML_TRUST_ANCHOR_EXISTS")
	}
	return nil
}

type effectiveTrust struct {
	TrustedKeys      []trustedKey `json:"trusted_keys"`
	RevokedKeys      []string     `json:"revoked_keys"`
	PolicySha256     any          `json:"policy_sha256"`
	RegistrySha256   any          `json:"registry_sha256"`
	ProfileSha256    any          `json:"profile_sha256"`
	RequireSingleUse bool         `json:"require_single_use"`
}

type trustDecision struct {
	Schema       string          `json:"schema"`
	Trusted      bool            `json:"trusted"`
	Reasons      []string        `json:"reasons"`
	Checks       map[string]bool `json:"checks"`
	BodyError    string          `json:"body_error,omitempty"`
	ConfigSha256 string          `json:"config_sha256,omitempty"`
	Version      int64           `json:"version,omitempty"`
	ExpiresAt    string          `json:"expires_at,omitempty"`
	Effective    *effectiveTrust `json:"effective,omitempty"`
}

func finishDecision(checks map[string]bool, d trustDecision) trustDecision {
	d.Schema = "aml-trust-config-decision/1"
	d.Reasons = []string{}
	for _, name := range trustChecks {
		if !checks[name] {
			d.Reasons = append(d.Reasons, name)
		}
	}
	d.Trusted = len(d.Reasons) == 0
	d.Checks = checks
	return d
}

// evaluateTrustConfig mirrors runtime/trustConfig.js. beforePersist is a test seam.
func evaluateTrustConfig(envelope any, dir string, callerTime string, beforePersist func()) trustDecision {
	checks := map[string]bool{}
	for _, n := range trustChecks {
		checks[n] = false
	}
	checks["anchor_present"] = enrolled(dir)
	if !checks["anchor_present"] {
		return finishDecision(checks, trustDecision{})
	}
	st, err := readState(dir)
	if err != nil {
		return finishDecision(checks, trustDecision{})
	}
	checks["state_readable"] = true
	bodyErr := "envelope"
	var body *trustBody
	env, ok := envelope.(map[string]any)
	sigs, sigsOk := env["signatures"].([]any)
	if ok && sameStrings(sortedKeys(env), []string{"signatures", "signed"}) && sigsOk && len(sigs) <= maxTrustKeys {
		body, bodyErr = validateBody(env["signed"])
	}
	checks["envelope_well_formed"] = bodyErr == ""
	if bodyErr != "" {
		return finishDecision(checks, trustDecision{BodyError: bodyErr})
	}
	canon, err := canonical(body.raw)
	if err != nil {
		return finishDecision(checks, trustDecision{BodyError: "canonical"})
	}
	sum := sha256.Sum256([]byte(canon))
	configSha := hex.EncodeToString(sum[:])
	checks["root_threshold_met"] = countThreshold(sigs, []byte(canon), st.root) >= st.root.Threshold
	a, b := append([]string{}, body.root.Keyids...), append([]string{}, st.root.Keyids...)
	sort.Strings(a)
	sort.Strings(b)
	same := body.root.Threshold == st.root.Threshold && sameStrings(a, b)
	checks["new_root_threshold_met"] = same || countThreshold(sigs, []byte(canon), body.root) >= body.root.Threshold
	var latest int64
	if st.latest != nil {
		latest = st.latest.Version
	}
	checks["not_rolled_back"] = body.version >= latest
	var existing *stateRecord
	for i := range st.records {
		if st.records[i].Version == body.version {
			existing = &st.records[i]
		}
	}
	checks["no_version_fork"] = existing == nil || existing.ConfigSha256 == configSha
	now := time.Now().UnixMilli()
	checks["caller_time_absent"] = callerTime == ""
	checks["trusted_time"] = !st.hasFloor || now >= st.floor
	checks["issued_not_in_future"] = now >= body.issuedMs
	checks["not_expired"] = now < body.expiresMs
	for _, n := range trustChecks {
		if n != "state_persisted" && !checks[n] {
			return finishDecision(checks, trustDecision{ConfigSha256: configSha, Version: body.version})
		}
	}
	persist := func() error {
		if beforePersist != nil {
			beforePersist()
		}
		if existing == nil {
			set := map[string]bool{}
			for k := range st.revoked {
				set[k] = true
			}
			for _, k := range body.revoked {
				set[k] = true
			}
			rev := []string{}
			for k := range set {
				rev = append(rev, k)
			}
			sort.Strings(rev)
			rec := stateRecord{trustStateRecordType, body.version, configSha, body.root, rev, body.raw["issued_at"].(string), isoFromMs(now)}
			data, _ := json.Marshal(rec)
			path := filepath.Join(dir, "versions", fmt.Sprintf("v%012d.json", body.version))
			created, err := createExclusiveDurable(path, append(data, '\n'))
			if err != nil {
				return err
			}
			if !created {
				rv, err := readJSONLoose(path)
				if err != nil {
					return err
				}
				if rm, _ := rv.(map[string]any); rm == nil || rm["config_sha256"] != configSha {
					checks["no_version_fork"] = false
					return errors.New("fork")
				}
			}
		}
		after, err := readState(dir)
		if err != nil {
			return err
		}
		checks["not_rolled_back"] = after.latest.Version == body.version
		st = after
		checks["state_persisted"] = checks["not_rolled_back"]
		return nil
	}
	if err := persist(); err != nil {
		checks["state_persisted"] = false
		if !checks["no_version_fork"] {
			return finishDecision(checks, trustDecision{ConfigSha256: configSha})
		}
	}
	keys := []trustedKey{}
	for _, k := range body.keys {
		if !st.revoked[k.Keyid] && !contains(body.revoked, k.Keyid) {
			keys = append(keys, k)
		}
	}
	rev := []string{}
	for k := range st.revoked {
		rev = append(rev, k)
	}
	sort.Strings(rev)
	return finishDecision(checks, trustDecision{ConfigSha256: configSha, Version: body.version, ExpiresAt: body.raw["expires_at"].(string),
		Effective: &effectiveTrust{keys, rev, body.raw["policy_sha256"], body.raw["registry_sha256"], body.raw["profile_sha256"], body.raw["require_single_use"].(bool)}})
}

func enrolledDirs(extra []string, systemDir string) []string {
	out := []string{}
	for _, d := range append([]string{systemDir}, extra...) {
		if d == "" {
			continue
		}
		full, err := filepath.Abs(d)
		if err != nil || contains(out, full) || !enrolled(full) {
			continue
		}
		out = append(out, full)
	}
	return out
}

func evaluateTrustConfigAll(envelope any, dirs []string, callerTime string) trustDecision {
	if len(dirs) == 0 {
		return trustDecision{Schema: "aml-trust-config-decision/1", Reasons: []string{"anchor_present"}, Checks: map[string]bool{"anchor_present": false}}
	}
	var first trustDecision
	revoked := map[string]bool{}
	for i, d := range dirs {
		dec := evaluateTrustConfig(envelope, d, callerTime, nil)
		if !dec.Trusted {
			return dec
		}
		if i == 0 {
			first = dec
		}
		for _, k := range dec.Effective.RevokedKeys {
			revoked[k] = true
		}
	}
	eff := *first.Effective
	eff.RevokedKeys = []string{}
	for k := range revoked {
		eff.RevokedKeys = append(eff.RevokedKeys, k)
	}
	sort.Strings(eff.RevokedKeys)
	keys := []trustedKey{}
	for _, k := range first.Effective.TrustedKeys {
		if !revoked[k.Keyid] {
			keys = append(keys, k)
		}
	}
	eff.TrustedKeys = keys
	first.Effective = &eff
	return first
}

func stillUnexpired(d trustDecision) bool {
	ms, ok := isoMs(d.ExpiresAt)
	return ok && time.Now().UnixMilli() < ms
}

func trustsKey(d trustDecision, keyid, role string) bool {
	if !d.Trusted || len(d.Reasons) != 0 || d.Effective == nil || !stillUnexpired(d) || !hex64Re.MatchString(keyid) || !contains(trustRoles, role) {
		return false
	}
	if contains(d.Effective.RevokedKeys, keyid) {
		return false
	}
	for _, k := range d.Effective.TrustedKeys {
		if k.Keyid == keyid && contains(k.Roles, role) {
			return true
		}
	}
	return false
}

func pinMatches(d trustDecision, field, actual string) bool {
	if !d.Trusted || d.Effective == nil || !stillUnexpired(d) {
		return false
	}
	var pin any
	switch field {
	case "policy_sha256":
		pin = d.Effective.PolicySha256
	case "registry_sha256":
		pin = d.Effective.RegistrySha256
	case "profile_sha256":
		pin = d.Effective.ProfileSha256
	default:
		return false
	}
	return isHex64(pin) && pin.(string) == actual
}

// requiresSingleUse fails closed: only a trusted config with require_single_use false does not require it.
func requiresSingleUse(d *trustDecision) bool {
	return !(d != nil && d.Trusted && d.Effective != nil && !d.Effective.RequireSingleUse)
}

// ---------- durable single-use store ----------
func consumptionKey(parts []string) (string, error) {
	if len(parts) == 0 {
		return "", errors.New("AML_CONSUMPTION_KEY_INVALID")
	}
	for _, p := range parts {
		if p == "" || strings.ContainsRune(p, 0) {
			return "", errors.New("AML_CONSUMPTION_KEY_INVALID")
		}
	}
	sum := sha256.Sum256([]byte("aml-consumption/1\x00" + strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:]), nil
}

func consume(storeDir, key string, record map[string]any) (bool, error) {
	if !hex64Re.MatchString(key) {
		return false, errors.New("AML_CONSUMPTION_KEY_INVALID")
	}
	abs, err := filepath.Abs(storeDir)
	if err != nil {
		return false, err
	}
	dir := filepath.Join(abs, "consumed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	body := map[string]any{}
	for k, v := range record {
		body[k] = v
	}
	body["type"], body["key"], body["consumed_at"], body["pid"] = "aml-consumption-record/1", key, isoFromMs(time.Now().UnixMilli()), os.Getpid()
	data, _ := json.Marshal(body)
	return createExclusiveDurable(filepath.Join(dir, key+".json"), append(data, '\n'))
}

// ---------- trust options shared by the Go commands ----------
type trustOptions struct {
	config, state, store string
}

type trustMode struct {
	decision *trustDecision
	dirs     []string
}

func resolveTrustMode(o trustOptions, callerTime string) (*trustMode, error) {
	dirs := enrolledDirs([]string{o.state, os.Getenv("AML_TRUST_STATE_DIR")}, systemTrustStateDir)
	if o.config == "" && len(dirs) == 0 {
		return nil, nil
	}
	if o.config == "" {
		return &trustMode{nil, dirs}, nil
	}
	data, err := os.ReadFile(o.config)
	if err != nil {
		return nil, err
	}
	env, err := strictJSON(data)
	if err != nil {
		return nil, err
	}
	if callerTime == "" {
		callerTime = os.Getenv("AML_VERIFY_AT")
	}
	d := evaluateTrustConfigAll(env, dirs, callerTime)
	return &trustMode{&d, dirs}, nil
}

type trustSummary struct {
	Mode         string   `json:"mode"`
	Trusted      bool     `json:"trusted"`
	Reasons      []string `json:"reasons"`
	Version      int64    `json:"version,omitempty"`
	ConfigSha256 string   `json:"config_sha256,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
}

func summarize(t *trustMode) *trustSummary {
	if t == nil {
		return nil
	}
	if t.decision == nil {
		return &trustSummary{Mode: "trust-config", Reasons: []string{"trust_config_missing"}}
	}
	d := t.decision
	return &trustSummary{"trust-config", d.Trusted, d.Reasons, d.Version, d.ConfigSha256, d.ExpiresAt}
}

// ---------- subcommands ----------
func takeTrustFlags(args []string) ([]string, trustOptions, error) {
	o := trustOptions{}
	rest := []string{}
	for i := 0; i < len(args); i++ {
		var target *string
		switch args[i] {
		case "--trust-config":
			target = &o.config
		case "--trust-state":
			target = &o.state
		case "--single-use-store":
			target = &o.store
		}
		if target == nil {
			rest = append(rest, args[i])
			continue
		}
		if *target != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return nil, o, fmt.Errorf("%s requires exactly one value", args[i])
		}
		*target = args[i+1]
		i++
	}
	return rest, o, nil
}

func runTrustVerify(args []string) int {
	rest, o, err := takeTrustFlags(args)
	if err == nil && len(rest) != 0 {
		err = errors.New("unexpected arguments")
	}
	var t *trustMode
	if err == nil {
		t, err = resolveTrustMode(o, "")
	}
	if err != nil {
		data, _ := json.Marshal(map[string]any{"authorized": false, "error": err.Error()})
		fmt.Println(string(data))
		return 2
	}
	trusted := t != nil && t.decision != nil && t.decision.Trusted && len(t.decision.Reasons) == 0
	// Same top-level shape as `aml trust-verify` and trust_config.py trust-verify.
	out := map[string]any{"authorized": trusted, "decision_use": notAnAuthorizationDecision, "mode": "explicit-pins"}
	if s := summarize(t); s != nil {
		out["mode"], out["trusted"], out["reasons"] = s.Mode, s.Trusted, s.Reasons
		out["version"], out["config_sha256"], out["expires_at"], out["effective"] = nil, nil, nil, nil
		if s.Version != 0 {
			out["version"] = s.Version
		}
		if s.ConfigSha256 != "" {
			out["config_sha256"] = s.ConfigSha256
		}
		if s.ExpiresAt != "" {
			out["expires_at"] = s.ExpiresAt
		}
	}
	if trusted {
		out["decision_use"] = "trust-config"
		out["effective"] = t.decision.Effective
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(data))
	if trusted {
		return exitAuthorized
	}
	return exitNotAuthorized
}

func runTrustConformance(path string) int {
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
	cases := v.(map[string]any)["cases"].([]any)
	results := []any{}
	for _, c := range cases {
		cm := c.(map[string]any)
		work, err := os.MkdirTemp("", "aml-tc-go-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		steps, err := runCase(cm, work)
		os.RemoveAll(work)
		if err != nil {
			fmt.Fprintln(os.Stderr, cm["name"], err)
			return 2
		}
		results = append(results, map[string]any{"name": cm["name"], "steps": steps})
	}
	out, _ := json.Marshal(map[string]any{"implementation": "go", "results": results})
	fmt.Println(string(out))
	return 0
}

func runCase(c map[string]any, work string) ([]any, error) {
	stateDir := filepath.Join(work, "state")
	anchor := c["anchor"].(map[string]any)
	ids := []string{}
	for _, k := range anchor["keyids"].([]any) {
		ids = append(ids, k.(string))
	}
	th, _ := asInt(anchor["threshold"])
	if err := initTrustState(stateDir, th, ids); err != nil {
		return nil, err
	}
	out := []any{}
	for _, s := range c["steps"].([]any) {
		step := s.(map[string]any)
		if before, ok := step["before"].(map[string]any); ok {
			if err := applyBefore(before, stateDir); err != nil {
				return nil, err
			}
		}
		if cons, ok := step["consume"].(map[string]any); ok {
			parts := []string{}
			for _, p := range cons["parts"].([]any) {
				parts = append(parts, p.(string))
			}
			key, err := consumptionKey(parts)
			if err != nil {
				return nil, err
			}
			ok, err := consume(filepath.Join(work, "store"), key, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, map[string]any{"key": key, "consumed": ok})
			continue
		}
		envelope := step["envelope"]
		if text, ok := step["envelope_text"].(string); ok {
			parsed, err := strictJSON([]byte(text))
			if err != nil {
				out = append(out, map[string]any{"parse_error": true})
				continue
			}
			envelope = parsed
		}
		var hook func()
		if race, ok := step["race_envelope"]; ok {
			hook = func() { evaluateTrustConfig(race, stateDir, "", nil) }
		}
		caller, _ := step["caller_time"].(string)
		d := evaluateTrustConfig(envelope, stateDir, caller, hook)
		answers := []any{}
		if qs, ok := step["queries"].([]any); ok {
			for _, q := range qs {
				qm := q.(map[string]any)
				switch qm["kind"] {
				case "key":
					answers = append(answers, trustsKey(d, qm["keyid"].(string), qm["role"].(string)))
				case "pin":
					actual, _ := qm["actual"].(string)
					answers = append(answers, pinMatches(d, qm["field"].(string), actual))
				case "single_use":
					answers = append(answers, requiresSingleUse(&d))
				}
			}
		}
		res := map[string]any{"trusted": d.Trusted, "reasons": d.Reasons, "version": nil, "config_sha256": nil, "effective": nil, "answers": answers}
		if d.Version != 0 {
			res["version"] = d.Version
		}
		if d.Trusted {
			res["config_sha256"] = d.ConfigSha256
			res["effective"] = d.Effective
		}
		out = append(out, res)
	}
	return out, nil
}

func applyBefore(b map[string]any, stateDir string) error {
	versions := filepath.Join(stateDir, "versions")
	switch b["kind"] {
	case "floor_future":
		v, _ := asInt(b["version"])
		path := filepath.Join(versions, fmt.Sprintf("v%012d.json", v))
		rv, err := readJSONLoose(path)
		if err != nil {
			return err
		}
		rm := rv.(map[string]any)
		rm["accepted_at"] = isoFromMs(time.Now().UnixMilli() + 86400000)
		data, _ := json.Marshal(rm)
		return os.WriteFile(path, data, 0o600)
	case "write_state_file":
		return os.WriteFile(filepath.Join(versions, b["name"].(string)), []byte(b["contents"].(string)), 0o600)
	case "remove_state_file":
		return os.Remove(filepath.Join(versions, b["name"].(string)))
	}
	return fmt.Errorf("unknown before action %v", b["kind"])
}
