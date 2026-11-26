"""Testes da avaliação passiva de CORS."""

from __future__ import annotations

from sentinela.analyzers.cors import analyze_cors
from tests.factories import make_snapshot


def test_coringa_com_credenciais_e_sinalizado() -> None:
    findings = analyze_cors(
        make_snapshot(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
    )
    assert "cors.wildcard_credentials" in {finding.code for finding in findings}


def test_origem_explicita_com_credenciais_exige_vary() -> None:
    headers = {
        "Access-Control-Allow-Origin": "https://exemplo.test",
        "Access-Control-Allow-Credentials": "true",
    }
    without_vary = {finding.code for finding in analyze_cors(make_snapshot(headers))}
    assert "cors.missing_vary" in without_vary

    headers["Vary"] = "Origin"
    with_vary = {finding.code for finding in analyze_cors(make_snapshot(headers))}
    assert "cors.explicit_credentials" in with_vary
    assert "cors.missing_vary" not in with_vary
