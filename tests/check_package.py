"""Offline syntax and metadata checks; run the Hermes CLI validator separately.

Keeping these checks separate avoids launching an unbootstrapped Python child
from managed Hermes runtimes. See plugin/README.md for both validation gates.
"""
import ast
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SDK = os.environ.get("HERMES_SOURCE")
if SDK:
    sys.path.insert(0, str(Path(SDK).expanduser().resolve()))
sys.dont_write_bytecode = True


def main():
    with tempfile.TemporaryDirectory(prefix="isolated-", dir=ROOT / "tests") as scratch:
        os.environ.clear()
        os.environ.update(HOME=scratch, HERMES_HOME=scratch,
                          HERMES_GATEWAY_LOCK_DIR=str(Path(scratch) / "locks"),
                          PYTHONDONTWRITEBYTECODE="1", PATH="/usr/bin:/bin")
        if SDK:
            os.environ["PYTHONPATH"] = str(Path(SDK).expanduser().resolve())
        import yaml

        for folder in ("plugin", "tests"):
            for source in (ROOT / folder).glob("*.py"):
                ast.parse(source.read_text(), filename=str(source))
        print("Python syntax: PASS")

        manifest = yaml.safe_load((ROOT / "plugin/plugin.yaml").read_text())
        entry = yaml.safe_load((ROOT / "plugin-catalog/nextcloud-talk.yaml").read_text())
        assert entry["name"] == manifest["name"] == "nextcloud-talk"
        assert entry["version"] == manifest["version"] == "0.2.1"
        assert entry["subdir"] == "plugin"
        assert entry["tier"] == "community" and entry["category"] == "platform"
        for key in ("provides_tools", "provides_hooks", "provides_middleware"):
            assert entry["capabilities"][key] == manifest[key] == []
        assert set(entry["capabilities"]["requires_env"]) == {
            item["name"] for item in manifest["requires_env"]}
        assert entry["repo"].startswith("https://")
        for path in (ROOT / "README.md", ROOT / "plugin/README.md", ROOT / "plugin/CHANGES.md"):
            text = path.read_text()
            # Generic home-directory paths, not a list of a developer's identities.
            assert not re.search(r"/(?:home|Users)/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\", text), path
        print("Catalog metadata/version/capability alignment and public documentation: PASS")
        unresolved = [key for key in ("repo", "sha", "maintainer")
                      if "REPLACE_" in str(entry[key])]
        if unresolved:
            print("NOT SUBMISSION-READY: replace " + ", ".join(unresolved))
        else:
            assert re.fullmatch(r"[0-9a-fA-F]{40}", entry["sha"])
            print("SHA format checked only; remote pinned source not verified by this offline check.")
        if not (ROOT / "LICENSE").is_file() and not (ROOT / "plugin/LICENSE").is_file():
            print("PUBLICATION TODO: select and add a license.")
        print("Run hermes plugins validate ./plugin --install-deps separately in an isolated development environment.")
        print("These offline checks do not establish catalog acceptance or remote installation.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
