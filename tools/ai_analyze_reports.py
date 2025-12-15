#!/usr/bin/env python3
"""
Generate a cybersecurity-expert-style analysis report from WebRecon JSON outputs.

Provider routing:
- Prefer OpenAI if OPENAI_API_KEY is set and /v1/models is reachable
- Else try OpenAI-compatible local servers (OPENAI_COMPAT_BASE_URL or common localhost ports)
- Else try Ollama (OLLAMA_HOST)
- Else fall back to deterministic offline analysis (tools/analyze_reports.py)

Outputs:
- Markdown report (default: webrecon_output/analysis_ai.md)
- HTML wrapper (default: webrecon_output/analysis_ai.html)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _http_json(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout_s: int = 30,
) -> Any:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    models: list[str]


def _probe_openai_models(base_url: str, api_key: str, timeout_s: int) -> Provider | None:
    try:
        data = _http_json(
            "GET",
            base_url.rstrip("/") + "/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout_s=timeout_s,
        )
        items = data.get("data") if isinstance(data, dict) else None
        models: list[str] = []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and it.get("id"):
                    models.append(str(it["id"]))
        models = sorted(set(models))
        if not models:
            return None
        return Provider(name="openai", base_url=base_url.rstrip("/"), models=models)
    except Exception:
        return None


def _probe_openai_compat_models(base_url: str, api_key: str | None, timeout_s: int) -> Provider | None:
    try:
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        data = _http_json("GET", base_url.rstrip("/") + "/v1/models", headers=headers, timeout_s=timeout_s)
        items = data.get("data") if isinstance(data, dict) else None
        models: list[str] = []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and it.get("id"):
                    models.append(str(it["id"]))
        models = sorted(set(models))
        if not models:
            return None
        return Provider(name="openai_compat", base_url=base_url.rstrip("/"), models=models)
    except Exception:
        return None


def _probe_ollama(host: str, timeout_s: int) -> Provider | None:
    try:
        data = _http_json("GET", host.rstrip("/") + "/api/tags", timeout_s=timeout_s)
        items = data.get("models") if isinstance(data, dict) else None
        models: list[str] = []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and it.get("name"):
                    models.append(str(it["name"]))
        models = sorted(set(models))
        if not models:
            return None
        return Provider(name="ollama", base_url=host.rstrip("/"), models=models)
    except Exception:
        return None


def _choose_best_model(provider: Provider) -> str:
    # Allow explicit override
    explicit = os.environ.get("ANALYSIS_MODEL") or os.environ.get("OPENAI_MODEL") or ""
    if explicit and explicit in provider.models:
        return explicit

    models = provider.models

    if provider.name in {"openai", "openai_compat"}:
        preference = [
            "gpt-4.1",
            "gpt-4o",
            "chatgpt-4o-latest",
            "gpt-4o-mini",
            "gpt-4",
        ]
        for pref in preference:
            for m in models:
                if m == pref or m.startswith(pref + "-"):
                    return m
        # Fallback: first gpt*
        for m in models:
            if m.startswith("gpt-"):
                return m
        return models[0]

    if provider.name == "ollama":
        preferred = [
            os.environ.get("OLLAMA_MODEL", ""),
            "llama3.1",
            "llama3.2",
            "qwen2.5",
            "mistral",
        ]
        for pref in preferred:
            if not pref:
                continue
            for m in models:
                if m == pref or m.startswith(pref + ":"):
                    return m
        return models[0]

    return models[0]


def _render_html_from_markdown(md: str, title: str) -> str:
    # We keep this dependency-free: render markdown as preformatted text.
    escaped = html.escape(md)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; padding: 24px; }}
    pre {{ white-space: pre-wrap; word-wrap: break-word; }}
    .meta {{ color: #555; margin-bottom: 16px; }}
  </style>
</head>
<body>
  <div class="meta">{html.escape(title)}</div>
  <pre>{escaped}</pre>
</body>
</html>
"""


def _offline_fallback(reports: list[str]) -> str:
    # Use the deterministic analyzer already in the repo.
    cmd = [sys.executable, str(Path(__file__).parent / "analyze_reports.py")] + reports
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return f"# Analysis failed\n\nOffline analyzer error:\n\n{result.stderr}\n"
    return result.stdout


def _call_openai_chat(provider: Provider, model: str, api_key: str, prompt: str, timeout_s: int) -> str:
    url = provider.base_url.rstrip("/") + "/v1/chat/completions"
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior cybersecurity consultant. Analyze OSINT/web-recon scan results. "
                    "Be evidence-based: do not invent findings not supported by the data. "
                    "For each domain, summarize observed behavior, risks, and prioritized recommendations. "
                    "Call out HTTP→HTTPS redirect posture, exposed emails, WAF/bot blocking (e.g. 403), "
                    "and any third-party tooling indicators. Provide next-step validation checks."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    resp = _http_json(
        "POST",
        url,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        body=body,
        timeout_s=timeout_s,
    )
    choices = resp.get("choices") if isinstance(resp, dict) else None
    if isinstance(choices, list) and choices:
        msg = choices[0].get("message", {})
        content = msg.get("content")
        if isinstance(content, str):
            return content
    raise RuntimeError("Unexpected OpenAI chat response schema")


def _call_ollama_chat(provider: Provider, model: str, prompt: str, timeout_s: int) -> str:
    # Ollama API: POST /api/chat
    url = provider.base_url.rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": "You are a senior cybersecurity consultant. Be evidence-based."},
            {"role": "user", "content": prompt},
        ],
    }
    resp = _http_json("POST", url, headers={"Content-Type": "application/json"}, body=body, timeout_s=timeout_s)
    msg = resp.get("message") if isinstance(resp, dict) else None
    if isinstance(msg, dict) and isinstance(msg.get("content"), str):
        return str(msg["content"])
    raise RuntimeError("Unexpected Ollama chat response schema")


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-assisted security analysis of WebRecon JSON reports.")
    parser.add_argument("reports", nargs="+", help="Paths to WebRecon JSON report files.")
    parser.add_argument("--out-md", default="webrecon_output/analysis_ai.md", help="Output Markdown path.")
    parser.add_argument("--out-html", default="webrecon_output/analysis_ai.html", help="Output HTML path.")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout seconds per API call.")
    args = parser.parse_args()

    report_paths = [str(Path(p).expanduser().resolve()) for p in args.reports]

    # Load inputs (small, safe to embed)
    payload = []
    for p in report_paths:
        payload.append({"path": os.path.basename(p), "json": json.loads(Path(p).read_text(encoding="utf-8"))})

    prompt = (
        "Here are WebRecon scan results (JSON) for multiple domains and schemes. "
        "Write a professional security assessment in Markdown.\n\n"
        "Requirements:\n"
        "- Start with an Executive Summary.\n"
        "- For each domain: compare HTTP vs HTTPS behavior, include redirects, crawlability, and tech signals.\n"
        "- Provide risks (with severity), and clear, actionable recommendations.\n"
        "- If results are minimal, explain why (e.g. parked pages, WAF blocking, limited crawl scope).\n"
        "- Do NOT claim vulnerabilities without evidence.\n\n"
        f"DATA:\n{json.dumps(payload, indent=2)}\n"
    )

    # Provider routing
    timeout_s = int(args.timeout)
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    openai_base = os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com"

    provider: Provider | None = None
    if openai_key:
        provider = _probe_openai_models(openai_base, openai_key, timeout_s=10)

    if not provider:
        compat = os.environ.get("OPENAI_COMPAT_BASE_URL") or ""
        candidates = [compat] if compat else ["http://127.0.0.1:1234", "http://127.0.0.1:8080", "http://127.0.0.1:8000"]
        for c in candidates:
            if not c:
                continue
            provider = _probe_openai_compat_models(c, openai_key or None, timeout_s=3)
            if provider:
                break

    if not provider:
        ollama_host = os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"
        provider = _probe_ollama(ollama_host, timeout_s=3)

    # Generate analysis
    title = f"WebRecon AI Analysis ({_dt.datetime.utcnow().isoformat()}Z)"
    if not provider:
        md = _offline_fallback(report_paths)
        md = f"# {title}\n\n(Offline fallback — no LLM provider available)\n\n" + md
    else:
        model = _choose_best_model(provider)
        if provider.name in {"openai", "openai_compat"}:
            if not openai_key:
                md = _offline_fallback(report_paths)
                md = f"# {title}\n\n(Offline fallback — no OPENAI_API_KEY)\n\n" + md
            else:
                md_body = _call_openai_chat(provider, model, openai_key, prompt, timeout_s=timeout_s)
                md = f"# {title}\n\nProvider: `{provider.name}`  Model: `{model}`\n\n" + md_body.strip() + "\n"
        elif provider.name == "ollama":
            md_body = _call_ollama_chat(provider, model, prompt, timeout_s=timeout_s)
            md = f"# {title}\n\nProvider: `{provider.name}`  Model: `{model}`\n\n" + md_body.strip() + "\n"
        else:
            md = _offline_fallback(report_paths)
            md = f"# {title}\n\n(Offline fallback — unknown provider)\n\n" + md

    out_md = Path(args.out_md).expanduser().resolve()
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(md, encoding="utf-8")

    out_html = Path(args.out_html).expanduser().resolve()
    out_html.write_text(_render_html_from_markdown(md, title), encoding="utf-8")

    print(f"Wrote: {out_md}")
    print(f"Wrote: {out_html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


