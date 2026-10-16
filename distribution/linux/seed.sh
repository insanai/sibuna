#!/bin/sh
# Creates the admission seed (64 hexadecimal digits) once, as the service user.
# An existing seed is checked, never replaced: rotating it would end every session.
set -eu
seed=${1:?usage: seed.sh <path>}
directory=$(dirname "$seed")
fail() {
    echo "sibuna-seed: $*" >&2
    exit 1
}
private() {
    # Prints success when "$1" is owned by us and grants the group and others nothing.
    [ -O "$1" ] || return 1
    case $(stat -c %a "$1") in
        *00) return 0 ;;
        *) return 1 ;;
    esac
}
private "$directory" || fail "$directory must be owned by the service user with mode 0700"
if [ -e "$seed" ] || [ -L "$seed" ]; then
    [ -f "$seed" ] && [ ! -L "$seed" ] || fail "$seed must be a regular file"
    private "$seed" || fail "$seed must be owned by the service user with mode 0600"
    exit 0
fi
umask 077
temporary=$(mktemp "$directory/.admission-XXXXXX")
trap 'rm -f "$temporary"' EXIT
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$temporary"
[ "$(wc -c < "$temporary")" -eq 64 ] || fail "could not read 32 random bytes"
sync "$temporary"
# A hard link never replaces an existing file, so two racing starts keep one seed.
ln "$temporary" "$seed" 2>/dev/null || true
private "$seed" || fail "$seed must be owned by the service user with mode 0600"
