"""Ordering, grouping and replacement rules of the migration roadmap."""

from datetime import datetime

from quantum_tool import migration_engine as me

NOW = datetime(2020, 6, 30, 0, 0, 0)

KYBER768 = {
    "algorithm": "Kyber768", "kind": "kem", "public_key_len": 1184, "secret_key_len": 2400,
    "ciphertext_len": 1088, "keygen_ms": 0.05, "encap_ms": 0.06, "decap_ms": 0.05,
}
DILITHIUM3 = {
    "algorithm": "DILITHIUM_3", "kind": "sig", "public_key_len": 1472, "secret_key_len": 3504,
    "signature_len": 2701, "keygen_ms": 0.2, "sign_ms": 0.6, "verify_ms": 0.2,
}


def finding(target, component, algorithm, threat_class, threat_level="critical"):
    return {"target": target, "component": component, "algorithm": algorithm,
            "threat_class": threat_class, "threat_level": threat_level,
            "recommendation": "see roadmap"}


def assessment(target, risk, *specs):
    return {"target": target, "risk_score": risk,
            "findings": [finding(target, *spec) for spec in specs]}


def keys(roadmap):
    return [(p["component"], p["algorithm"]) for p in roadmap["phases"]]


def test_empty_input_gives_empty_roadmap():
    roadmap = me.build_roadmap([], now=NOW)
    assert roadmap == {"generated_at": "2020-06-30T00:00:00Z", "phases": []}


def test_assessments_without_actionable_findings_give_no_phases():
    clean = assessment("a:443", 0, ("cipher", "AES-256", "none", "low"))
    assert me.build_roadmap([clean, assessment("b:443", 0)], now=NOW)["phases"] == []


def test_phases_are_ordered_by_max_risk():
    roadmap = me.build_roadmap([
        assessment("low:443", 5, ("cipher", "AES-128", "grover", "medium")),
        assessment("high:443", 85, ("key_exchange", "RSA", "shor")),
        assessment("mid:443", 60, ("authentication", "ECDSA", "shor")),
    ], now=NOW)
    assert keys(roadmap) == [("key_exchange", "RSA"), ("authentication", "ECDSA"),
                             ("cipher", "AES-128")]
    assert [p["max_risk"] for p in roadmap["phases"]] == [85, 60, 5]
    assert [p["priority"] for p in roadmap["phases"]] == [1, 2, 3]


def test_targets_sharing_an_algorithm_are_grouped():
    roadmap = me.build_roadmap([
        assessment("b:443", 70, ("key_exchange", "ECDH", "shor")),
        assessment("a:443", 60, ("key_exchange", "ECDH", "shor")),
        assessment("c:443", 60, ("authentication", "ECDSA", "shor")),
    ], now=NOW)
    ecdh = [p for p in roadmap["phases"] if p["algorithm"] == "ECDH"]
    assert len(ecdh) == 1
    assert ecdh[0]["targets"] == ["a:443", "b:443"]
    assert ecdh[0]["max_risk"] == 70
    assert len(roadmap["phases"]) == 2


def test_same_algorithm_in_different_components_stays_separate():
    roadmap = me.build_roadmap([
        assessment("a:443", 70, ("key_exchange", "RSA", "shor"),
                   ("authentication", "RSA", "shor"), ("certificate_key", "RSA", "shor")),
    ], now=NOW)
    assert sorted(keys(roadmap)) == [("authentication", "RSA"), ("certificate_key", "RSA"),
                                     ("key_exchange", "RSA")]


def test_classical_and_grover_follow_shor_at_the_same_score():
    roadmap = me.build_roadmap([
        assessment("a:443", 85,
                   ("cipher", "AES-128", "grover", "medium"),
                   ("certificate_signature", "SHA-1", "classical", "high"),
                   ("key_exchange", "RSA", "shor")),
    ], now=NOW)
    assert [p["threat_class"] for p in roadmap["phases"]] == ["shor", "classical", "grover"]


def test_target_count_breaks_ties_within_a_threat_class():
    roadmap = me.build_roadmap([
        assessment("a:443", 60, ("key_exchange", "ECDH", "shor"),
                   ("authentication", "ECDSA", "shor")),
        assessment("b:443", 60, ("authentication", "ECDSA", "shor")),
    ], now=NOW)
    assert keys(roadmap) == [("authentication", "ECDSA"), ("key_exchange", "ECDH")]


def test_replacements_follow_the_component_and_algorithm():
    roadmap = me.build_roadmap([
        assessment("a:443", 100,
                   ("key_exchange", "DH", "shor"),
                   ("authentication", "RSA", "shor"),
                   ("certificate_key", "ECDSA", "shor"),
                   ("cipher", "3DES", "classical", "high"),
                   ("cipher", "RC4", "classical", "high"),
                   ("cipher", "AES-128", "grover", "medium"),
                   ("mac", "HMAC-SHA1", "classical", "medium"),
                   ("certificate_signature", "SHA-1", "classical", "high"),
                   ("certificate_signature", "MD5", "classical", "high"),
                   ("certificate_signature", "SHA-256", "grover", "low")),
        assessment("/keys/server.key", 50, ("certificate_key", "RSA", "shor")),
    ], now=NOW)
    replacement = {(p["component"], p["algorithm"]): p["replacement"]
                   for p in roadmap["phases"]}
    assert replacement[("key_exchange", "DH")] == "Kyber768"
    assert replacement[("authentication", "RSA")] == "DILITHIUM_3"
    assert replacement[("certificate_key", "ECDSA")] == "DILITHIUM_3"
    assert replacement[("certificate_key", "RSA")] == "DILITHIUM_3"
    assert replacement[("cipher", "3DES")] == "AES-256-GCM"
    assert replacement[("cipher", "RC4")] == "AES-256-GCM"
    assert replacement[("cipher", "AES-128")] == "AES-256-GCM"
    assert "AEAD" in replacement[("mac", "HMAC-SHA1")]
    assert replacement[("certificate_signature", "SHA-1")] == "SHA-384"
    assert replacement[("certificate_signature", "MD5")] == "SHA-384"
    assert replacement[("certificate_signature", "SHA-256")] == "SHA-384"

    alternatives = {(p["component"], p["algorithm"]): p["alternative"]
                    for p in roadmap["phases"]}
    assert alternatives[("authentication", "RSA")] == "SPHINCS+-SHA256-128f-simple"
    assert alternatives[("key_exchange", "DH")] is None
    assert alternatives[("cipher", "3DES")] is None


def test_only_shor_phases_carry_a_hybrid_note():
    roadmap = me.build_roadmap([
        assessment("a:443", 85, ("key_exchange", "RSA", "shor"),
                   ("cipher", "AES-128", "grover", "medium")),
    ], now=NOW)
    shor, grover = roadmap["phases"]
    assert "Kyber" in shor["hybrid"] and "ECDHE" in shor["hybrid"]
    assert grover["hybrid"] is None


def test_bench_is_attached_to_matching_phases_only():
    roadmap = me.build_roadmap([
        assessment("a:443", 85, ("key_exchange", "ECDH", "shor"),
                   ("certificate_key", "RSA", "shor"),
                   ("cipher", "AES-128", "grover", "medium")),
    ], bench=[KYBER768], now=NOW)
    bench = {p["algorithm"]: p["bench"] for p in roadmap["phases"]}
    assert bench["ECDH"] == KYBER768
    assert bench["RSA"] is None
    assert bench["AES-128"] is None


def test_bench_omitted_leaves_every_phase_without_figures():
    roadmap = me.build_roadmap([
        assessment("a:443", 60, ("authentication", "ECDSA", "shor")),
    ], now=NOW)
    assert roadmap["phases"][0]["bench"] is None
    with_bench = me.build_roadmap([
        assessment("a:443", 60, ("authentication", "ECDSA", "shor")),
    ], bench=[KYBER768, DILITHIUM3], now=NOW)
    assert with_bench["phases"][0]["bench"] == DILITHIUM3


def test_roadmap_does_not_mutate_input():
    data = [assessment("a:443", 60, ("authentication", "ECDSA", "shor"))]
    snapshot = repr(data)
    me.build_roadmap(data, bench=[DILITHIUM3], now=NOW)
    assert repr(data) == snapshot


def test_generated_at_defaults_to_current_utc_time():
    stamp = me.build_roadmap([])["generated_at"]
    assert datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")


def test_unclassified_suites_get_a_review_phase_after_known_threats():
    roadmap = me.build_roadmap([
        assessment("a:443", 15, ("cipher_suite", "NOT-A-SUITE", "unknown", "high")),
        assessment("b:443", 15, ("cipher", "AES-128", "grover", "medium")),
    ], now=NOW)

    assert keys(roadmap) == [("cipher", "AES-128"), ("cipher_suite", "NOT-A-SUITE")]
    review = roadmap["phases"][1]
    assert review["threat_class"] == "unknown"
    assert review["replacement"] == "see roadmap"
    assert review["hybrid"] is None
