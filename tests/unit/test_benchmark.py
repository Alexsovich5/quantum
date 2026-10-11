import json

import oqs
import pytest

from quantum_tool.algorithms import benchmark

KEM_KEYS = {"algorithm", "kind", "public_key_len", "secret_key_len", "ciphertext_len",
            "keygen_ms", "encap_ms", "decap_ms"}
SIG_KEYS = {"algorithm", "kind", "public_key_len", "secret_key_len", "signature_len",
            "keygen_ms", "sign_ms", "verify_ms"}


def _details(cls, name):
    with cls(name) as native:
        return dict(native.details)


def test_kyber512_returns_one_kem_result_with_liboqs_sizes():
    results = benchmark.run(["Kyber512"], 2)
    details = _details(oqs.KeyEncapsulation, "Kyber512")

    assert len(results) == 1
    result = results[0]
    assert set(result) == KEM_KEYS
    assert result["algorithm"] == "Kyber512"
    assert result["kind"] == "kem"
    assert result["ciphertext_len"] == details["length_ciphertext"]
    assert result["public_key_len"] == details["length_public_key"]
    assert result["secret_key_len"] == details["length_secret_key"]
    for key in ("keygen_ms", "encap_ms", "decap_ms"):
        assert isinstance(result[key], float)
        assert result[key] > 0


def test_signature_algorithm_returns_signature_len():
    results = benchmark.run(["DILITHIUM_2"], 1)
    details = _details(oqs.Signature, "DILITHIUM_2")

    assert len(results) == 1
    result = results[0]
    assert set(result) == SIG_KEYS
    assert result["kind"] == "sig"
    assert result["signature_len"] == details["length_signature"]
    assert result["public_key_len"] == details["length_public_key"]
    for key in ("keygen_ms", "sign_ms", "verify_ms"):
        assert result[key] > 0


def test_results_follow_requested_order_and_are_json_serialisable():
    results = benchmark.run(["DILITHIUM_2", "Kyber512"], 1)

    assert [r["algorithm"] for r in results] == ["DILITHIUM_2", "Kyber512"]
    assert json.loads(json.dumps(results)) == results


def test_default_set_covers_kyber_dilithium_and_sphincs():
    assert benchmark.DEFAULT_ALGORITHMS == (
        "Kyber512", "Kyber768", "DILITHIUM_2", "DILITHIUM_3", "SPHINCS+-SHA256-128f-simple",
    )


def test_unknown_name_raises_value_error():
    with pytest.raises(ValueError, match="NotAnAlgorithm"):
        benchmark.run(["NotAnAlgorithm"], 1)


def test_unknown_name_is_rejected_before_any_measurement(monkeypatch):
    calls = []
    monkeypatch.setattr(benchmark, "_bench_kem", lambda *a: calls.append(a))
    with pytest.raises(ValueError):
        benchmark.run(["Kyber512", "NotAnAlgorithm"], 1)
    assert calls == []


@pytest.mark.parametrize("iterations", [0, -1])
def test_iterations_below_one_raise(iterations):
    with pytest.raises(ValueError, match="iterations"):
        benchmark.run(["Kyber512"], iterations)
