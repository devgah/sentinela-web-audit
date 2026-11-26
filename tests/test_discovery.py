"""Testes de descoberta passiva com respostas sintéticas."""

from __future__ import annotations

from sentinela.analyzers.discovery import (
    _choose_sitemap_url,
    analyze_robots,
    analyze_security_txt,
    analyze_sitemap,
)
from tests.factories import make_text

_BASE = "https://exemplo.test/"


def test_robots_revela_caminhos_sensiveis() -> None:
    robots = make_text("User-agent: *\nDisallow: /admin\nDisallow: /.env\n")
    findings = analyze_robots(robots, _BASE)
    assert "discovery.robots.sensitive_paths" in {f.code for f in findings}


def test_sitemap_externo_nao_e_escolhido() -> None:
    robots = make_text("Sitemap: https://outro.test/sitemap.xml\n")
    url, external = _choose_sitemap_url(robots, _BASE)
    assert url == "https://exemplo.test/sitemap.xml"
    assert external is True


def test_sitemap_com_entidades_e_rejeitado() -> None:
    sitemap = make_text('<!DOCTYPE foo [<!ENTITY x "y">]><urlset></urlset>')
    findings = analyze_sitemap(sitemap, _BASE, False)
    assert "discovery.sitemap.entities" in {f.code for f in findings}


def test_security_txt_sem_contacto() -> None:
    document = make_text("Expires: 2099-01-01T00:00:00Z\n")
    findings = analyze_security_txt((document,))
    assert "discovery.security_txt.contact" in {f.code for f in findings}
