#!/usr/bin/env python3
"""Run the native renderer, optionally accepting reviewed golden changes."""
import argparse
import os
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("renderer")
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    environment = os.environ.copy()
    environment["SIBUNA_UPDATE_CONSOLE_GOLDENS"] = "1" if args.update else ""
    raise SystemExit(subprocess.call([args.renderer], env=environment))


if __name__ == "__main__":
    main()
