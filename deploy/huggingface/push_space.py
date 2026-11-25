#!/usr/bin/env python3
"""Assemble this repository's Hugging Face Space and upload it.

GitHub stays the source of the code: this script copies the files listed in
deploy/huggingface/space.json into a temporary folder (the Space layout) and uploads that
folder to the Space as one commit. Files on the Space that are no longer part of the layout
are removed. Nothing else on the Hub is changed: no secrets, variables or hardware.

    HF_TOKEN=hf_... python deploy/huggingface/push_space.py            # deploy
    python deploy/huggingface/push_space.py --dry-run                   # only show the layout

The token needs write access to the Space (a fine-grained token scoped to it is enough).
It is read from HF_TOKEN and never printed.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "space.json"
ALWAYS_EXCLUDE = ["**/__pycache__/**", "**/*.pyc", "**/.pytest_cache/**", "**/.env", "**/.env.*",
                  "**/*.key", "**/*.pem", "**/node_modules/**", "**/.DS_Store"]


def excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch("/" + rel, p) for p in patterns)


def assemble(manifest: dict, out: Path) -> list[str]:
    patterns = ALWAYS_EXCLUDE + manifest.get("exclude", [])
    written = []
    for src, dest in manifest["copy"].items():
        source = ROOT / src
        if not source.exists():
            raise SystemExit(f"missing in the repository: {src}")
        files = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
        for f in files:
            rel_src = f.relative_to(ROOT).as_posix()
            if excluded(rel_src, patterns):
                continue
            target = out / dest if source.is_file() else out / dest / f.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, target)
            written.append(target.relative_to(out).as_posix())
    if "README.md" not in written or ("Dockerfile" not in written and manifest.get("sdk", "docker") == "docker"):
        raise SystemExit("the Space layout needs a README.md (Space card) and a Dockerfile at its root")
    return sorted(written)


def git_revision() -> str:
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout
        return rev + ("-dirty" if dirty.strip() else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--space", help="owner/name of the Space (default: from the manifest or HF_SPACE)")
    ap.add_argument("--private", action="store_true", help="create the Space as private if it does not exist")
    ap.add_argument("--dry-run", action="store_true", help="assemble and list the files, upload nothing")
    ap.add_argument("--message", default=None, help="commit message on the Space")
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text())
    space = args.space or os.environ.get("HF_SPACE") or manifest["space"]
    with tempfile.TemporaryDirectory(prefix="hf-space-") as tmp:
        out = Path(tmp)
        files = assemble(manifest, out)
        print(f"Space {space}: {len(files)} files")
        for f in files:
            print("  " + f)
        if args.dry_run:
            return 0
        token = os.environ.get("HF_TOKEN")
        if not token:
            print("HF_TOKEN is not set", file=sys.stderr)
            return 2
        from huggingface_hub import HfApi

        api = HfApi(token=token)
        api.create_repo(space, repo_type="space", space_sdk=manifest.get("sdk", "docker"),
                        private=args.private, exist_ok=True)
        message = args.message or f"Deploy {manifest.get('source', ROOT.name)}@{git_revision()}"
        info = api.upload_folder(folder_path=str(out), repo_id=space, repo_type="space",
                                 commit_message=message, delete_patterns=["*"])
        print(f"Uploaded: {getattr(info, 'commit_url', info)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
