"""Use a saved signed fixture or prepare one through the native download command."""

from pathlib import Path


def arguments(parser):
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--candidate", type=Path)
    source.add_argument("--download", action="store_true")


def resolve(binary, args, root):
    if args.candidate:
        return args.candidate.resolve()
    from crs_daemon_check import candidate
    return candidate(binary, root)
