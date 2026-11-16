#!/usr/bin/env python3
"""Build this dependency-free static GitHub Pages site."""
from pathlib import Path
from shutil import copytree, rmtree

root = Path(__file__).resolve().parents[1]
output = root / "dist"
if output.exists():
    rmtree(output)
copytree(root / "web", output)
(output / ".nojekyll").touch()
print("Built", output.relative_to(root))
