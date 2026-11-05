"""Load a codebase from a local folder, a ZIP archive, or a public GitHub URL.

Everything read here is treated as untrusted data: archives are extracted with
path-traversal (zip-slip) and size protections, symlinks are not followed, and
nothing from the target is ever executed.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from .models import SourceFile

MAX_FILE_BYTES = 400_000          # skip individual files larger than this
MAX_TOTAL_BYTES = 8_000_000       # stop collecting after this many bytes of source
MAX_ARCHIVE_BYTES = 200_000_000   # refuse archives that expand beyond this
MAX_DOWNLOAD_BYTES = 100_000_000

LANGUAGE_BY_EXT = {
    ".ts": "typescript", ".tsx": "tsx", ".js": "javascript", ".jsx": "jsx",
    ".mjs": "javascript", ".cjs": "javascript", ".vue": "vue", ".svelte": "svelte",
    ".sql": "sql", ".py": "python", ".rb": "ruby", ".php": "php", ".go": "go",
    ".java": "java", ".kt": "kotlin", ".cs": "csharp", ".rs": "rust",
    ".html": "html", ".htm": "html", ".json": "json", ".yml": "yaml", ".yaml": "yaml",
    ".toml": "toml", ".xml": "xml", ".sh": "bash", ".env": "dotenv", ".ini": "ini",
    ".conf": "config", ".tf": "terraform", ".graphql": "graphql", ".prisma": "prisma",
}
SPECIAL_NAMES = {
    "dockerfile": "dockerfile", ".env": "dotenv", ".htaccess": "config",
    "nginx.conf": "config", "docker-compose.yml": "yaml",
}
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt", "coverage",
    "__pycache__", ".venv", "venv", "env", ".idea", ".vscode", "vendor", "target",
    ".turbo", ".cache", ".pytest_cache", ".mypy_cache", "bower_components",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
    "composer.lock", "Gemfile.lock", "go.sum",
}
# Low-value files for security review that would only add noise.
SKIP_SUFFIXES = (".min.js", ".map", ".d.ts", ".snap")
# Docs are not code; they are excluded from analysis so their prose (including any
# embedded instructions) never reaches the model as "code".
DOC_EXTS = {".md", ".markdown", ".rst", ".txt"}

GITHUB_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?"
    r"(?:/tree/(?P<ref>[^/]+)(?:/(?P<sub>.*))?)?/?$"
)


class IngestError(Exception):
    pass


def detect_language(path: str) -> str | None:
    p = PurePosixPath(path)
    name = p.name.lower()
    if name in SPECIAL_NAMES:
        return SPECIAL_NAMES[name]
    if name.startswith(".env"):
        return "dotenv"
    if name.endswith(SKIP_SUFFIXES):
        return None
    return LANGUAGE_BY_EXT.get(p.suffix.lower())


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def collect_files(root: Path, include_docs: bool = False) -> list[SourceFile]:
    """Walk ``root`` and return supported source files (repo-relative paths)."""
    root = root.resolve()
    files: list[SourceFile] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git"))
        for fname in sorted(filenames):
            full = Path(dirpath) / fname
            if full.is_symlink() or fname in SKIP_FILES:
                continue
            rel = full.relative_to(root).as_posix()
            lang = detect_language(rel)
            if lang is None and include_docs and full.suffix.lower() in DOC_EXTS:
                lang = "text"
            if lang is None:
                continue
            try:
                size = full.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES or size == 0:
                continue
            data = full.read_bytes()
            if _looks_binary(data):
                continue
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise IngestError(
                    f"Codebase exceeds {MAX_TOTAL_BYTES // 1_000_000} MB of source; "
                    "point the tool at a sub-folder."
                )
            files.append(SourceFile(rel, lang, data.decode("utf-8", errors="replace")))
    return files


def safe_extract_zip(data: bytes, dest: Path) -> Path:
    """Extract a ZIP with zip-slip, symlink and zip-bomb protections."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("Not a valid ZIP archive") from exc
    dest = dest.resolve()
    expanded = 0
    with zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("/") or ".." in PurePosixPath(name).parts or ":" in name:
                continue  # path traversal attempt; skip
            # Skip symlinks (unix mode in high bits)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            expanded += info.file_size
            if expanded > MAX_ARCHIVE_BYTES:
                raise IngestError("Archive expands beyond the allowed size")
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    # If the archive has a single top-level folder, use it as the root.
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "secreview-cli"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (https only)
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise IngestError("Download too large")
    return data


def _fetch_github(owner: str, repo: str, ref: str, dest: Path) -> Path:
    """Download a public repo as a ZIP; fall back to a shallow ``git clone`` if that fails."""
    errors = []
    for url in (f"https://codeload.github.com/{owner}/{repo}/zip/{ref}",
                f"https://github.com/{owner}/{repo}/archive/{ref}.zip"):
        try:
            return safe_extract_zip(_download(url), dest)
        except (urllib.error.URLError, OSError, IngestError) as exc:
            errors.append(f"{url}: {exc}")
    git = shutil.which("git")
    if git:
        target = dest / repo
        cmd = [git, "clone", "--depth", "1", "--quiet"]
        if ref != "HEAD":
            cmd += ["--branch", ref]
        cmd += ["--", f"https://github.com/{owner}/{repo}.git", str(target)]
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)  # noqa: S603
        if proc.returncode == 0:
            shutil.rmtree(target / ".git", ignore_errors=True)
            return target
        errors.append(f"git clone: {proc.stderr.strip()[:200]}")
    raise IngestError("Could not download repository:\n  " + "\n  ".join(errors))


class Workspace:
    """Resolves a target to a local directory; cleans up temp dirs on exit."""

    def __init__(self, target: str):
        self.target = target
        self._tmp: str | None = None
        self.root: Path | None = None
        self.name = ""

    def __enter__(self) -> "Workspace":
        t = self.target.strip()
        m = GITHUB_RE.match(t)
        if m:
            owner, repo = m["owner"], m["repo"]
            ref = m["ref"] or "HEAD"
            self._tmp = tempfile.mkdtemp(prefix="secreview-")
            root = _fetch_github(owner, repo, ref, Path(self._tmp))
            if m["sub"]:
                sub = (root / m["sub"]).resolve()
                if not str(sub).startswith(str(root.resolve())) or not sub.is_dir():
                    raise IngestError(f"Sub-path not found in repository: {m['sub']}")
                root = sub
            self.root = root
            self.name = f"{owner}/{repo}" + (f"/{m['sub']}" if m["sub"] else "")
        elif t.lower().endswith(".zip") and Path(t).is_file():
            self._tmp = tempfile.mkdtemp(prefix="secreview-")
            self.root = safe_extract_zip(Path(t).read_bytes(), Path(self._tmp))
            self.name = Path(t).stem
        elif Path(t).is_dir():
            self.root = Path(t).resolve()
            self.name = self.root.name
        else:
            raise IngestError(f"Target not found: {t} (expected folder, .zip, or GitHub URL)")
        return self

    def __exit__(self, *exc) -> None:
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)


def project_name(root: Path, default: str) -> str:
    """Use package.json/pyproject name if present for nicer report titles."""
    pkg = root / "package.json"
    if pkg.is_file():
        m = re.search(r'"name"\s*:\s*"([^"]+)"', pkg.read_text(errors="replace"))
        if m:
            return m.group(1)
    return default
