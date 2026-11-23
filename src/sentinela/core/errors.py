"""Erros de domínio da aplicação."""

from __future__ import annotations


class SentinelaError(Exception):
    """Base para erros esperados da aplicação."""


class InvalidTargetError(SentinelaError):
    """A URL informada não é um alvo HTTP(S) válido."""


class HttpRequestError(SentinelaError):
    """Falha ao obter a resposta HTTP do alvo."""
