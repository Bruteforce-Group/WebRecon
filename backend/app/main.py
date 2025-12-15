from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
SCANS_DIR = DATA_DIR / "scans"
ROUTER_ALLOWLIST = PROJECT_ROOT / "router" / "allowed_domains.txt"
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/", 1)[0]
    d = d.strip(".")
    if not d or "/" in d or " " in d:
        raise ValueError("Invalid domain")
    if not re.fullmatch(r"[a-z0-9.-]+", d):
        raise ValueError("Invalid domain characters")
    return d


def _scan_id() -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"


def _ensure_router_allowlist(domains: list[str]) -> None:
    ROUTER_ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    existing: list[str] = []
    if ROUTER_ALLOWLIST.exists():
        existing = [ln.strip() for ln in ROUTER_ALLOWLIST.read_text(encoding="utf-8").splitlines()]

    # Squid dstdomain matches subdomains when you specify the root domain; do not add ".domain" entries.
    wanted = {d for d in (_safe_domain(x) for x in domains)}
    merged = []
    for ln in existing:
        if not ln or ln.startswith("#"):
            continue
        try:
            merged.append(_safe_domain(ln))
        except Exception:
            continue
    merged_set = set(merged) | wanted
    merged_sorted = sorted(merged_set)

    ROUTER_ALLOWLIST.write_text("\n".join(merged_sorted) + "\n", encoding="utf-8")

    # Restart router to reload allowlist (safest)
    _run_compose(["up", "-d", "--force-recreate", "router"])


def _run_compose(args: list[str]) -> None:
    if not COMPOSE_FILE.exists():
        raise RuntimeError(f"Missing compose file at {COMPOSE_FILE}")
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE)] + args
    proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Docker compose failed: {proc.stderr.strip() or proc.stdout.strip()}")


def _run_webrecon(url: str, output_path: Path, max_pages: int, max_depth: int, ignore_robots: bool) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    args = [
        "run",
        "--rm",
        "--no-deps",
        "webrecon",
        url,
        "--max-pages",
        str(max_pages),
        "--max-depth",
        str(max_depth),
        "--no-images",
        "--no-dns",
        "--no-whois",
        "--no-wayback",
        "--no-builtwith",
        "--no-dnsdumpster",
        "--debug",
        "--output",
        str(output_path.relative_to(PROJECT_ROOT)),
    ]
    if ignore_robots:
        args.append("--ignore-robots")
    _run_compose(args)
    if not output_path.exists():
        raise RuntimeError(
            "WebRecon finished but the report file was not created at "
            f"'{output_path}'. This usually means the container couldn't write to the "
            "host path (missing docker-compose volume mount for ./data or permissions)."
        )


def _run_ai_analysis(report_paths: list[Path], out_md: Path, out_html: Path) -> None:
    cmd = [
        os.fspath(PROJECT_ROOT / ".venv" / "bin" / "python"),
        os.fspath(PROJECT_ROOT / "tools" / "ai_analyze_reports.py"),
        *[os.fspath(p) for p in report_paths],
        "--out-md",
        os.fspath(out_md),
        "--out-html",
        os.fspath(out_html),
    ]
    proc = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())


@dataclass
class ScanArtifact:
    domain: str
    scheme: Literal["http", "https"]
    report_path: str


class CreateScanRequest(BaseModel):
    domains: list[str] = Field(min_length=1)
    schemes: Literal["both", "http", "https"] = "both"
    max_pages: int = Field(default=5, ge=1, le=500)
    max_depth: int = Field(default=1, ge=0, le=10)
    ignore_robots: bool = True
    generate_ai_analysis: bool = True
    acknowledge_authorization: bool = Field(
        default=False,
        description="Must be true to run scans. You confirm you own the targets or are authorized to test them.",
    )


class CreateScanResponse(BaseModel):
    scan_id: str
    created_at: str
    artifacts: list[ScanArtifact]
    ai_analysis_md: str | None = None
    ai_analysis_html: str | None = None


app = FastAPI(title="WebRecon Full-Stack", version="0.1.0")


frontend_dir = PROJECT_ROOT / "frontend"
app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (frontend_dir / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "time": _utc_now()}


@app.post("/api/scans", response_model=CreateScanResponse)
def create_scan(req: CreateScanRequest) -> CreateScanResponse:
    if not req.acknowledge_authorization:
        raise HTTPException(status_code=400, detail="acknowledge_authorization must be true")

    try:
        domains = [_safe_domain(d) for d in req.domains]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    scan_id = _scan_id()
    scan_dir = SCANS_DIR / scan_id
    reports_dir = scan_dir / "reports"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "meta.json").write_text(
        json.dumps({"scan_id": scan_id, "created_at": _utc_now(), "domains": domains}, indent=2),
        encoding="utf-8",
    )

    try:
        # Ensure router knows about these domains
        _ensure_router_allowlist(domains)
        artifacts: list[ScanArtifact] = []
        scheme_list: list[str]
        if req.schemes == "both":
            scheme_list = ["http", "https"]
        else:
            scheme_list = [req.schemes]

        for domain in domains:
            for scheme in scheme_list:
                url = f"{scheme}://{domain}"
                out_path = reports_dir / f"{domain.replace('.', '')}_{scheme}.json"
                _run_webrecon(
                    url,
                    out_path,
                    max_pages=req.max_pages,
                    max_depth=req.max_depth,
                    ignore_robots=req.ignore_robots,
                )
                artifacts.append(
                    ScanArtifact(domain=domain, scheme=scheme, report_path=str(out_path.relative_to(PROJECT_ROOT)))
                )

        ai_md = scan_dir / "analysis_ai.md"
        ai_html = scan_dir / "analysis_ai.html"
        if req.generate_ai_analysis:
            try:
                _run_ai_analysis([PROJECT_ROOT / a.report_path for a in artifacts], ai_md, ai_html)
            except Exception as e:
                # Still return scan artifacts even if analysis fails
                (scan_dir / "analysis_error.txt").write_text(str(e), encoding="utf-8")

        return CreateScanResponse(
            scan_id=scan_id,
            created_at=_utc_now(),
            artifacts=artifacts,
            ai_analysis_md=str(ai_md.relative_to(PROJECT_ROOT)) if ai_md.exists() else None,
            ai_analysis_html=str(ai_html.relative_to(PROJECT_ROOT)) if ai_html.exists() else None,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/api/scans/{scan_id}/file")
def get_scan_file(scan_id: str, path: str) -> FileResponse:
    # Only allow serving files from within the scan directory
    scan_dir = (SCANS_DIR / scan_id).resolve()
    candidate = (PROJECT_ROOT / path).resolve()
    if not str(candidate).startswith(str(scan_dir)):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not candidate.exists():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(candidate)


