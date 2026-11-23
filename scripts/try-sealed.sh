#!/bin/sh
# usage: scripts/try-sealed.sh <op://vault/item/field> [--account <acct>]
#
# Tries Secure Enclave mode by hand, against your real 1Password account, with
# Touch ID. The tests can't: they fake the Secure Enclave.
#
# It builds opcli, signs it ad hoc (no certificate, no entitlements), and runs
# it as opcli-try with HOME set to a temporary directory, so its data
# directory (and so the mode) is separate from any opcli you have installed.
# That HOME has no login keychain, and needs none: this mode never stores
# anything in a keychain. 1Password's database is read where it is.
set -u
cd "$(dirname "$0")/.."
ref=${1:?usage: scripts/try-sealed.sh <op://vault/item/field> [--account <acct>]}
shift

db="$HOME/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data/1password.sqlite"
try=$(mktemp -d)
trap 'rm -rf "$try"' EXIT
make opcli >/dev/null || { echo "build FAILED"; exit 1; }
cp opcli "$try/opcli-try"
codesign --force --sign - "$try/opcli-try" || exit 1
mkdir "$try/home"
run() { HOME="$try/home" OPCLI_DB_PATH="$db" "$try/opcli-try" "$@"; }
pass=0 fail=0
check() { if [ "$1" -eq "$2" ]; then echo "PASS  $3"; pass=$((pass + 1)); else echo "FAIL  $3 (exit $1, want $2)"; fail=$((fail + 1)); fi; }

echo ">> Signing in (asks for your account password; no Touch ID yet)"
run signin --secure-enclave "$@" || { echo "signin FAILED"; exit 1; }
ls -l "$try/home/.opcli"

printf '\n>> Press Enter, then APPROVE Touch ID in the opcli window (it should list %s; no second macOS prompt should follow) ' "$ref"; read -r _
OPCLI_TIMING=1 run read "$ref" "$@" >/dev/null; check $? 0 "read after Touch ID"

printf '\n>> Press Enter: the same read asks AGAIN (no approvals are kept). APPROVE it ' ; read -r _
run read "$ref" "$@" >/dev/null; check $? 0 "second read, second prompt"

printf '\n>> Press Enter, then click Cancel in the opcli window ' ; read -r _
run read "$ref" "$@" >/dev/null 2>&1; check $? 3 "cancelled Touch ID exits 3"

printf "\n>> Signing out\n"
run signout "$@"; check $? 0 "signout"
[ -z "$(ls -A "$try/home/.opcli")" ]; check $? 0 "signout removed the sealed files and the key handle"

printf "\n%d passed, %d failed\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
