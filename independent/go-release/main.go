package main

import (
    "bytes"
    "crypto/ed25519"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "errors"
    "fmt"
    "os"
    "sort"
    "strconv"
    "strings"
    "time"
)

const (
    proofProtocol          = "aml-semantic-release-proof/1"
    proofVersion           = "1.0"
    proofAlgorithm         = "Ed25519"
    proofMaterialProtocol  = "aml-semantic-release-proof-material/1"
    manifestProtocol       = "aml-meaning-manifest/1"
    manifestVersion        = "1.0"
    manifestAlgorithm      = "sha256"
    manifestMaterial       = "aml-meaning-manifest-material/1"
    fingerprintProtocol    = "aml-meaning-fingerprint/1"
    manifestAttestProtocol = "aml-meaning-manifest-attestation/1"
    lineageProtocol        = "aml-meaning-lineage/1"
    lineageEntryProtocol   = "aml-meaning-lineage-entry/1"
)

type result struct {
    Protocol                  string   `json:"protocol"`
    VerifiedEnvelope          bool     `json:"verified_envelope"`
    FullSemanticVerified      bool     `json:"full_semantic_verified"`
    ManifestIntegrityValid    bool     `json:"manifest_integrity_valid"`
    ManifestSignaturesValid   bool     `json:"manifest_signatures_valid"`
    LineageValid              bool     `json:"lineage_valid"`
    LineageAdjacencyValid     bool     `json:"lineage_adjacency_valid"`
    ChangeStructureValid      bool     `json:"change_structure_valid"`
    ProofHashValid            bool     `json:"proof_hash_valid"`
    PublicKeyFingerprintValid bool     `json:"public_key_fingerprint_valid"`
    SignatureValid            bool     `json:"signature_valid"`
    ProofSHA256               string   `json:"proof_sha256,omitempty"`
    ReleaseID                 any      `json:"release_id,omitempty"`
    Signer                    any      `json:"signer,omitempty"`
    Limitations               []string `json:"limitations"`
    Reason                    string   `json:"reason,omitempty"`
}

func baseResult() result {
    return result{
        Protocol:             "aml-go-semantic-release-envelope-result/1",
        FullSemanticVerified: false,
        Limitations: []string{
            "does_not_recompute_meaning_fingerprints_from_source_snapshots",
            "does_not_recompute_semantic_diff_from_aml_source",
        },
    }
}

func decodeJSON(data []byte) (map[string]any, error) {
    dec := json.NewDecoder(bytes.NewReader(data))
    dec.UseNumber()
    var v any
    if err := dec.Decode(&v); err != nil { return nil, err }
    if dec.More() { return nil, errors.New("trailing JSON") }
    m, ok := v.(map[string]any)
    if !ok { return nil, errors.New("top-level JSON must be object") }
    return m, nil
}

func canonicalJSON(v any) ([]byte, error) {
    var b bytes.Buffer
    if err := writeCanonical(&b, v); err != nil { return nil, err }
    return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
    switch x := v.(type) {
    case nil:
        b.WriteString("null")
    case bool:
        if x { b.WriteString("true") } else { b.WriteString("false") }
    case string:
        raw, _ := json.Marshal(x)
        s := string(raw)
        s = strings.ReplaceAll(s, `\u003c`, "<")
        s = strings.ReplaceAll(s, `\u003e`, ">")
        s = strings.ReplaceAll(s, `\u0026`, "&")
        s = strings.ReplaceAll(s, `\u2028`, string(rune(0x2028)))
        s = strings.ReplaceAll(s, `\u2029`, string(rune(0x2029)))
        b.WriteString(s)
    case json.Number:
        s := string(x)
        if strings.ContainsAny(s, ".eE") {
            f, err := strconv.ParseFloat(s, 64)
            if err != nil { return err }
            b.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
        } else {
            if _, err := strconv.ParseInt(s, 10, 64); err != nil {
                f, ferr := strconv.ParseFloat(s, 64)
                if ferr != nil { return err }
                b.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
            } else {
                b.WriteString(s)
            }
        }
    case float64:
        b.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
    case []any:
        b.WriteByte('[')
        for i, item := range x {
            if i > 0 { b.WriteByte(',') }
            if err := writeCanonical(b, item); err != nil { return err }
        }
        b.WriteByte(']')
    case map[string]any:
        keys := make([]string, 0, len(x))
        for k := range x { keys = append(keys, k) }
        sort.Strings(keys)
        b.WriteByte('{')
        for i, k := range keys {
            if i > 0 { b.WriteByte(',') }
            if err := writeCanonical(b, k); err != nil { return err }
            b.WriteByte(':')
            if err := writeCanonical(b, x[k]); err != nil { return err }
        }
        b.WriteByte('}')
    default:
        return fmt.Errorf("unsupported canonical JSON type %T", v)
    }
    return nil
}

func shaHex(data []byte) string {
    sum := sha256.Sum256(data)
    return hex.EncodeToString(sum[:])
}

func str(m map[string]any, key string) (string, bool) {
    v, ok := m[key].(string)
    return v, ok
}

func obj(m map[string]any, key string) (map[string]any, bool) {
    v, ok := m[key].(map[string]any)
    return v, ok
}

func arr(m map[string]any, key string) ([]any, bool) {
    v, ok := m[key].([]any)
    return v, ok
}

func numberInt(v any) (int, bool) {
    n, ok := v.(json.Number)
    if !ok { return 0, false }
    i, err := strconv.Atoi(string(n))
    return i, err == nil
}

func validHash(s string) bool {
    if len(s) != 64 { return false }
    _, err := hex.DecodeString(s)
    return err == nil && s == strings.ToLower(s)
}

func parseEd25519PEM(text string) (ed25519.PublicKey, []byte, error) {
    block, rest := pem.Decode([]byte(text))
    if block == nil || len(bytes.TrimSpace(rest)) != 0 { return nil, nil, errors.New("invalid public key PEM") }
    key, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil { return nil, nil, err }
    pub, ok := key.(ed25519.PublicKey)
    if !ok { return nil, nil, errors.New("public key is not Ed25519") }
    return pub, block.Bytes, nil
}

func manifestMaterialFor(manifest map[string]any) (map[string]any, error) {
    files, ok := arr(manifest, "files")
    if !ok || len(files) == 0 { return nil, errors.New("manifest files invalid") }
    materialFiles := make([]any, 0, len(files))
    previous := ""
    for i, raw := range files {
        f, ok := raw.(map[string]any); if !ok { return nil, errors.New("manifest file invalid") }
        path, pok := str(f, "path"); fp, fok := str(f, "fingerprint"); av, aok := str(f, "amt_version")
        if !pok || path == "" || !fok || !validHash(fp) || !aok || av == "" { return nil, errors.New("manifest file field invalid") }
        if i > 0 && previous >= path { return nil, errors.New("manifest paths not sorted") }
        previous = path
        materialFiles = append(materialFiles, map[string]any{"path": path, "fingerprint": fp, "amt_version": av})
    }
    return map[string]any{"protocol": manifestMaterial, "fingerprint_protocol": fingerprintProtocol, "files": materialFiles}, nil
}

func verifyManifest(manifest map[string]any) bool {
    p, _ := str(manifest, "protocol"); v, _ := str(manifest, "version"); a, _ := str(manifest, "algorithm")
    mp, _ := str(manifest, "material_protocol"); fp, _ := str(manifest, "fingerprint_protocol"); root, rok := str(manifest, "root_sha256")
    files, fok := arr(manifest, "files"); count, cok := numberInt(manifest["file_count"])
    if p != manifestProtocol || v != manifestVersion || a != manifestAlgorithm || mp != manifestMaterial || fp != fingerprintProtocol || !rok || !validHash(root) || !fok || !cok || count != len(files) || count == 0 { return false }
    material, err := manifestMaterialFor(manifest); if err != nil { return false }
    bytes, err := canonicalJSON(material); if err != nil { return false }
    return shaHex(bytes) == root
}

func attestationMaterial(att map[string]any) map[string]any {
    signer := att["signer"]
    if _, ok := att["signer"]; !ok { signer = nil }
    return map[string]any{
        "protocol": manifestAttestProtocol,
        "version": "1.0",
        "algorithm": "Ed25519",
        "manifest_protocol": att["manifest_protocol"],
        "manifest_version": att["manifest_version"],
        "manifest_material_protocol": att["manifest_material_protocol"],
        "fingerprint_protocol": att["fingerprint_protocol"],
        "manifest_root_sha256": att["manifest_root_sha256"],
        "file_count": att["file_count"],
        "signer": signer,
        "signed_at": att["signed_at"],
    }
}

func verifyManifestAttestation(att, manifest map[string]any) bool {
    if !verifyManifest(manifest) { return false }
    p, _ := str(att, "protocol"); v, _ := str(att, "version"); alg, _ := str(att, "algorithm")
    if p != manifestAttestProtocol || v != "1.0" || alg != "Ed25519" { return false }
    signedAt, ok := str(att, "signed_at"); if !ok { return false }
    if _, err := time.Parse(time.RFC3339Nano, signedAt); err != nil { return false }
    manifestRoot, _ := str(manifest, "root_sha256"); attRoot, _ := str(att, "manifest_root_sha256")
    if att["manifest_protocol"] != manifest["protocol"] || att["manifest_version"] != manifest["version"] || att["manifest_material_protocol"] != manifest["material_protocol"] || att["fingerprint_protocol"] != manifest["fingerprint_protocol"] || attRoot != manifestRoot || fmt.Sprint(att["file_count"]) != fmt.Sprint(manifest["file_count"]) { return false }
    pemText, ok := str(att, "public_key_pem"); if !ok { return false }
    pub, der, err := parseEd25519PEM(pemText); if err != nil { return false }
    declaredFP, ok := str(att, "public_key_sha256"); if !ok || shaHex(der) != declaredFP { return false }
    sigText, ok := str(att, "signature_base64"); if !ok { return false }
    sig, err := base64.StdEncoding.Strict().DecodeString(sigText); if err != nil { return false }
    materialBytes, err := canonicalJSON(attestationMaterial(att)); if err != nil { return false }
    return ed25519.Verify(pub, materialBytes, sig)
}

func lineageEntryMaterial(entry map[string]any) map[string]any {
    return map[string]any{
        "protocol": lineageEntryProtocol,
        "version": "1.0",
        "sequence": entry["sequence"],
        "previous_entry_sha256": entry["previous_entry_sha256"],
        "semantic_changed": entry["semantic_changed"],
        "previous_manifest_root_sha256": entry["previous_manifest_root_sha256"],
        "manifest_root_sha256": entry["manifest_root_sha256"],
        "manifest": entry["manifest"],
        "attestation": entry["attestation"],
    }
}

func verifyLineage(lineage map[string]any) (bool, string) {
    p, _ := str(lineage, "protocol"); v, _ := str(lineage, "version"); entries, ok := arr(lineage, "entries")
    if p != lineageProtocol || v != "1.0" || !ok { return false, "" }
    var prev map[string]any
    head := ""
    for i, raw := range entries {
        e, ok := raw.(map[string]any); if !ok { return false, "" }
        ep, _ := str(e, "protocol"); ev, _ := str(e, "version"); seq, sok := numberInt(e["sequence"])
        if ep != lineageEntryProtocol || ev != "1.0" || !sok || seq != i { return false, "" }
        expectedPrevEntry := any(nil); expectedPrevRoot := any(nil); expectedChanged := any(nil)
        if prev != nil {
            expectedPrevEntry = prev["entry_sha256"]
            expectedPrevRoot = prev["manifest_root_sha256"]
            expectedChanged = prev["manifest_root_sha256"] != e["manifest_root_sha256"]
        }
        if fmt.Sprint(e["previous_entry_sha256"]) != fmt.Sprint(expectedPrevEntry) || fmt.Sprint(e["previous_manifest_root_sha256"]) != fmt.Sprint(expectedPrevRoot) || fmt.Sprint(e["semantic_changed"]) != fmt.Sprint(expectedChanged) { return false, "" }
        manifest, mok := obj(e, "manifest"); att, aok := obj(e, "attestation"); if !mok || !aok { return false, "" }
        root, _ := str(e, "manifest_root_sha256"); mr, _ := str(manifest, "root_sha256"); ar, _ := str(att, "manifest_root_sha256")
        if root == "" || root != mr || root != ar || !verifyManifestAttestation(att, manifest) { return false, "" }
        materialBytes, err := canonicalJSON(lineageEntryMaterial(e)); if err != nil { return false, "" }
        expectedHash := shaHex(materialBytes); declared, ok := str(e, "entry_sha256"); if !ok || declared != expectedHash { return false, "" }
        head = declared; prev = e
    }
    return true, head
}

func canonicalEqual(a, b any) bool {
    aa, err := canonicalJSON(a); if err != nil { return false }
    bb, err := canonicalJSON(b); if err != nil { return false }
    return bytes.Equal(aa, bb)
}

func verifyAdjacency(proof map[string]any, lineage map[string]any, head string) bool {
    entries, ok := arr(lineage, "entries"); if !ok || len(entries) < 2 { return false }
    beforeEntry, bok := entries[len(entries)-2].(map[string]any); afterEntry, aok := entries[len(entries)-1].(map[string]any); if !bok || !aok { return false }
    beforeManifest, _ := obj(proof, "before_manifest"); afterManifest, _ := obj(proof, "after_manifest"); beforeAtt, _ := obj(proof, "before_attestation"); afterAtt, _ := obj(proof, "after_attestation")
    declaredHead, _ := str(proof, "lineage_head_sha256")
    return head == declaredHead && afterEntry["entry_sha256"] == declaredHead && beforeEntry["manifest_root_sha256"] == beforeManifest["root_sha256"] && afterEntry["manifest_root_sha256"] == afterManifest["root_sha256"] && canonicalEqual(beforeEntry["manifest"], beforeManifest) && canonicalEqual(beforeEntry["attestation"], beforeAtt) && canonicalEqual(afterEntry["manifest"], afterManifest) && canonicalEqual(afterEntry["attestation"], afterAtt)
}

func manifestIndex(manifest map[string]any) map[string]map[string]any {
    out := map[string]map[string]any{}
    files, _ := arr(manifest, "files")
    for _, raw := range files { if f, ok := raw.(map[string]any); ok { if p, ok := str(f, "path"); ok { out[p] = f } } }
    return out
}

func verifyChangeStructure(proof map[string]any) bool {
    beforeManifest, bok := obj(proof, "before_manifest"); afterManifest, aok := obj(proof, "after_manifest"); changes, cok := arr(proof, "changes"); summary, sok := obj(proof, "change_summary")
    if !bok || !aok || !cok || !sok { return false }
    before := manifestIndex(beforeManifest); after := manifestIndex(afterManifest)
    set := map[string]bool{}; for p := range before { set[p] = true }; for p := range after { set[p] = true }
    paths := make([]string,0,len(set)); for p := range set { paths=append(paths,p) }; sort.Strings(paths)
    if len(changes) != len(paths) { return false }
    counts := map[string]int{"added":0,"removed":0,"changed":0,"unchanged":0}
    for i, path := range paths {
        c, ok := changes[i].(map[string]any); if !ok { return false }; cp, _ := str(c,"path"); kind, _ := str(c,"kind"); if cp != path { return false }
        left, hasLeft := before[path]; right, hasRight := after[path]
        expected := ""
        if !hasLeft { expected="added" } else if !hasRight { expected="removed" } else if left["fingerprint"] == right["fingerprint"] && left["amt_version"] == right["amt_version"] { expected="unchanged" } else { expected="changed" }
        if kind != expected { return false }; counts[kind]++
        expectedBefore := any(nil); expectedAfter := any(nil); if hasLeft { expectedBefore=left["fingerprint"] }; if hasRight { expectedAfter=right["fingerprint"] }
        if fmt.Sprint(c["before_fingerprint"]) != fmt.Sprint(expectedBefore) || fmt.Sprint(c["after_fingerprint"]) != fmt.Sprint(expectedAfter) { return false }
    }
    for k, v := range counts { n, ok := numberInt(summary[k]); if !ok || n != v { return false } }
    return true
}

func proofMaterialFor(proof map[string]any) map[string]any {
    signer := proof["signer"]; if _, ok := proof["signer"]; !ok { signer=nil }
    return map[string]any{
        "protocol": proofMaterialProtocol,
        "proof_protocol": proofProtocol,
        "proof_version": proofVersion,
        "algorithm": proofAlgorithm,
        "release_id": proof["release_id"],
        "previous_release_id": proof["previous_release_id"],
        "generated_at": proof["generated_at"],
        "signer": signer,
        "public_key_sha256": proof["public_key_sha256"],
        "before_manifest": proof["before_manifest"],
        "before_attestation": proof["before_attestation"],
        "after_manifest": proof["after_manifest"],
        "after_attestation": proof["after_attestation"],
        "lineage": proof["lineage"],
        "lineage_head_sha256": proof["lineage_head_sha256"],
        "before_manifest_root_sha256": proof["before_manifest_root_sha256"],
        "after_manifest_root_sha256": proof["after_manifest_root_sha256"],
        "semantic_changed": proof["semantic_changed"],
        "change_summary": proof["change_summary"],
        "changes": proof["changes"],
    }
}

func verify(proof map[string]any) result {
    r := baseResult(); r.ReleaseID=proof["release_id"]; r.Signer=proof["signer"]
    p,_:=str(proof,"protocol"); v,_:=str(proof,"version"); a,_:=str(proof,"algorithm"); mp,_:=str(proof,"material_protocol")
    if p!=proofProtocol || v!=proofVersion || a!=proofAlgorithm || mp!=proofMaterialProtocol { r.Reason="invalid_release_proof_contract"; return r }
    generatedAt, ok := str(proof,"generated_at"); if !ok { r.Reason="invalid_generated_at"; return r }; if _,err:=time.Parse(time.RFC3339Nano,generatedAt); err!=nil { r.Reason="invalid_generated_at"; return r }
    before, bok:=obj(proof,"before_manifest"); after,aok:=obj(proof,"after_manifest"); beforeAtt,baok:=obj(proof,"before_attestation"); afterAtt,aaok:=obj(proof,"after_attestation"); lineage,lok:=obj(proof,"lineage")
    if !bok||!aok||!baok||!aaok||!lok { r.Reason="invalid_nested_artifacts"; return r }
    r.ManifestIntegrityValid=verifyManifest(before)&&verifyManifest(after); if !r.ManifestIntegrityValid { r.Reason="manifest_integrity_invalid"; return r }
    r.ManifestSignaturesValid=verifyManifestAttestation(beforeAtt,before)&&verifyManifestAttestation(afterAtt,after); if !r.ManifestSignaturesValid { r.Reason="manifest_signature_invalid"; return r }
    var head string; r.LineageValid,head=verifyLineage(lineage); if !r.LineageValid { r.Reason="lineage_invalid"; return r }
    r.LineageAdjacencyValid=verifyAdjacency(proof,lineage,head); if !r.LineageAdjacencyValid { r.Reason="lineage_adjacency_invalid"; return r }
    beforeRoot,_:=str(proof,"before_manifest_root_sha256"); afterRoot,_:=str(proof,"after_manifest_root_sha256"); bmr,_:=str(before,"root_sha256"); amr,_:=str(after,"root_sha256")
    if !validHash(beforeRoot)||!validHash(afterRoot)||beforeRoot!=bmr||afterRoot!=amr { r.Reason="release_root_binding_mismatch"; return r }
    changed,ok:=proof["semantic_changed"].(bool); if !ok || changed!=(beforeRoot!=afterRoot) { r.Reason="semantic_change_flag_mismatch"; return r }
    r.ChangeStructureValid=verifyChangeStructure(proof); if !r.ChangeStructureValid { r.Reason="change_structure_invalid"; return r }
    materialBytes,err:=canonicalJSON(proofMaterialFor(proof)); if err!=nil { r.Reason="canonicalization_error"; return r }
    expectedHash:=shaHex(materialBytes); r.ProofSHA256=expectedHash; declaredHash,ok:=str(proof,"proof_sha256"); r.ProofHashValid=ok&&validHash(declaredHash)&&declaredHash==expectedHash; if !r.ProofHashValid { r.Reason="proof_hash_mismatch"; return r }
    pemText,ok:=str(proof,"public_key_pem"); if !ok { r.Reason="invalid_public_key"; return r }; pub,der,err:=parseEd25519PEM(pemText); if err!=nil { r.Reason="invalid_public_key"; return r }
    declaredFP,ok:=str(proof,"public_key_sha256"); r.PublicKeyFingerprintValid=ok&&validHash(declaredFP)&&shaHex(der)==declaredFP; if !r.PublicKeyFingerprintValid { r.Reason="public_key_fingerprint_mismatch"; return r }
    sigText,ok:=str(proof,"signature_base64"); if !ok { r.Reason="invalid_signature_encoding"; return r }; sig,err:=base64.StdEncoding.Strict().DecodeString(sigText); if err!=nil { r.Reason="invalid_signature_encoding"; return r }
    r.SignatureValid=ed25519.Verify(pub,materialBytes,sig); if !r.SignatureValid { r.Reason="signature_invalid"; return r }
    r.VerifiedEnvelope=true; return r
}

func main() {
    if len(os.Args)!=2 { fmt.Fprintln(os.Stderr,"Usage: aml-go-release-envelope <release-proof.json>"); os.Exit(2) }
    data,err:=os.ReadFile(os.Args[1]); if err!=nil { fmt.Fprintln(os.Stderr,err); os.Exit(2) }
    proof,err:=decodeJSON(data); if err!=nil { fmt.Fprintln(os.Stderr,err); os.Exit(2) }
    r:=verify(proof); out,_:=json.MarshalIndent(r,"","  "); fmt.Println(string(out)); if r.VerifiedEnvelope { os.Exit(0) }; os.Exit(1)
}
