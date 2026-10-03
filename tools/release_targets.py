#!/usr/bin/env python3
"""One native-runner and package contract shared by qualification and packaging."""
import json
import os
import sys

PLATFORMS = [
    {"runner": "ubuntu-22.04", "package": "linux-amd64", "target": "x86_64-linux-musl"},
    {"runner": "ubuntu-24.04-arm", "package": "linux-arm64", "target": "aarch64-linux-musl"},
    {"runner": "macos-15", "package": "macos-arm64", "target": "aarch64-macos.15.0"},
    {"runner": "macos-15-intel", "package": "macos-amd64", "target": "x86_64-macos.15.0"},
    {"runner": "windows-2022", "package": "windows-amd64", "target": "x86_64-windows-gnu"},
]
TARGETS = {platform["package"]: platform["target"] for platform in PLATFORMS}


if __name__ == "__main__":
    selected = sys.argv[1] if len(sys.argv) > 1 else "all"
    # A public tag must always qualify every advertised platform.
    if os.environ.get("GITHUB_REF", "").startswith("refs/tags/"):
        selected = "all"
    if selected != "all" and selected not in TARGETS:
        raise SystemExit("Unknown release platform")
    print(json.dumps([platform for platform in PLATFORMS
                      if selected == "all" or platform["package"] == selected]))
