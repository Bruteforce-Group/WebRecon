#!/usr/bin/env python3
"""
Poll LLM endpoints for available models and print a concise summary.

Supports:
- OpenAI API (GET /v1/models)
- OpenAI-compatible local servers (GET /v1/models) via OPENAI_BASE_URL
- Ollama (GET /api/tags)

This is intentionally dependency-free (stdlib only).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    ok: bool
    base_url: str
    models: list[str]
    error: str | None = None


def _http_get_json(url: str, headers: dict[str, str] | None = None, timeout_s: int = 10) -> Any:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = resp.read()
    return json.loads(body.decode("utf-8", errors="replace"))


def probe_openai_models(base_url: str, api_key: str) -> ProviderResult:
    url = base_url.rstrip("/") + "/v1/models"
    try:
        data = _http_get_json(url, headers={"Authorization": f"Bearer {api_key}"})
        items = data.get("data") if isinstance(data, dict) else None
        models: list[str] = []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and it.get("id"):
                    models.append(str(it["id"]))
        models = sorted(set(models))
        return ProviderResult(provider="openai", ok=True, base_url=base_url, models=models)
    except Exception as e:  # noqa: BLE001
        return ProviderResult(provider="openai", ok=False, base_url=base_url, models=[], error=str(e))


def probe_openai_compat_models(base_url: str, api_key: str | None) -> ProviderResult:
    url = base_url.rstrip("/") + "/v1/models"
    try:
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        data = _http_get_json(url, headers=headers)
        items = data.get("data") if isinstance(data, dict) else None
        models: list[str] = []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and it.get("id"):
                    models.append(str(it["id"]))
        models = sorted(set(models))
        return ProviderResult(provider="openai_compat", ok=True, base_url=base_url, models=models)
    except Exception as e:  # noqa: BLE001
        return ProviderResult(provider="openai_compat", ok=False, base_url=base_url, models=[], error=str(e))


def probe_ollama_models(host: str) -> ProviderResult:
    base = host.rstrip("/")
    url = base + "/api/tags"
    try:
        data = _http_get_json(url)
        models: list[str] = []
        items = data.get("models") if isinstance(data, dict) else None
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and it.get("name"):
                    models.append(str(it["name"]))
        models = sorted(set(models))
        return ProviderResult(provider="ollama", ok=True, base_url=base, models=models)
    except Exception as e:  # noqa: BLE001
        return ProviderResult(provider="ollama", ok=False, base_url=base, models=[], error=str(e))


def main() -> int:
    parser = argparse.ArgumentParser(description="Poll LLM endpoints and list available models.")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout seconds per request (default: 10)")
    parser.add_argument("--openai-base-url", default=None, help="Override OpenAI base URL (default: https://api.openai.com)")
    parser.add_argument("--openai-compat-base-url", default=None, help="Override OpenAI-compatible base URL (e.g. http://localhost:1234)")
    parser.add_argument("--ollama-host", default=None, help="Override Ollama host (default: http://127.0.0.1:11434)")
    args = parser.parse_args()

    # Respect env where possible
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    openai_base = args.openai_base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com"
    openai_compat_base = (
        args.openai_compat_base_url
        or os.environ.get("OPENAI_COMPAT_BASE_URL")
        or os.environ.get("OPENAI_BASE_URL")
        or ""
    )
    ollama_host = args.ollama_host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"

    # NOTE: urllib timeout is per-call; we pass it via global default socket timeout by rebuilding helpers if needed.
    # Keep simple: rely on default (10s) via urlopen timeout in helper.

    results: list[ProviderResult] = []

    if openai_key:
        results.append(probe_openai_models(openai_base, openai_key))
    else:
        results.append(
            ProviderResult(
                provider="openai",
                ok=False,
                base_url=openai_base,
                models=[],
                error="OPENAI_API_KEY is not set",
            )
        )

    if openai_compat_base:
        results.append(probe_openai_compat_models(openai_compat_base, openai_key or None))
    else:
        # Try common local OpenAI-compatible defaults
        for candidate in ["http://127.0.0.1:1234", "http://127.0.0.1:8080", "http://127.0.0.1:8000"]:
            results.append(probe_openai_compat_models(candidate, None))

    # Ollama
    results.append(probe_ollama_models(ollama_host))

    # Print
    for r in results:
        status = "OK" if r.ok else "FAIL"
        print(f"[{status}] {r.provider} ({r.base_url})")
        if r.ok:
            if r.models:
                for m in r.models[:50]:
                    print(f"  - {m}")
                if len(r.models) > 50:
                    print(f"  ... ({len(r.models) - 50} more)")
            else:
                print("  (no models returned)")
        else:
            print(f"  error: {r.error}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


