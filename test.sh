#!/usr/bin/env bash
#
# The whole suite: formatting (verified, not applied), go vet, golangci-lint
# and go test with the race detector. Exits non-zero on any failure.
#
# Usage: ./test.sh [-n]    -n disables colour

set -u

colour=1
if [ "${1:-}" = "-n" ] || [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
	colour=0
fi
if [ "$colour" = 1 ]; then
	green=$'\033[32m' red=$'\033[31m' reset=$'\033[0m'
else
	green='' red='' reset=''
fi

cd "$(dirname "$0")" || exit 1

total=0 passed=0 failed=0 skipped=0

pass() { total=$((total + 1)); passed=$((passed + 1)); echo "${green}PASS${reset} $1"; }
fail() { total=$((total + 1)); failed=$((failed + 1)); echo "${red}FAIL${reset} $1"; }

echo "== 0. Prerequisites =="
have_lint=0
if command -v go >/dev/null 2>&1; then
	pass "0.1 go is installed"
else
	fail "0.1 go is installed (required)"
fi
if command -v golangci-lint >/dev/null 2>&1; then
	have_lint=1
	pass "0.2 golangci-lint is installed"
else
	fail "0.2 golangci-lint is installed (required)"
fi

echo "== 1. Formatting =="
if [ "$have_lint" = 1 ]; then
	if diff=$(golangci-lint fmt --diff ./... 2>&1) && [ -z "$diff" ]; then
		pass "1.1 golangci-lint fmt --diff"
	else
		echo "$diff"
		fail "1.1 golangci-lint fmt --diff (run make fmt)"
	fi
else
	fail "1.1 golangci-lint fmt --diff (golangci-lint is missing)"
fi

echo "== 2. go vet =="
if go vet ./...; then
	pass "2.1 go vet"
else
	fail "2.1 go vet"
fi

echo "== 3. golangci-lint =="
if [ "$have_lint" = 1 ] && golangci-lint run ./...; then
	pass "3.1 golangci-lint run"
else
	fail "3.1 golangci-lint run"
fi

echo "== 4. go test =="
out=$(go test -race -count=1 ./... 2>&1)
status=$?
echo "$out"
while IFS= read -r line; do
	case "$line" in
	ok*) pass "4 $(echo "$line" | awk '{print $2}')" ;;
	FAIL$'\t'*) fail "4 $(echo "$line" | awk '{print $2}')" ;;
	\?*) total=$((total + 1)); skipped=$((skipped + 1)) ;;
	esac
done <<<"$out"
if [ "$status" -ne 0 ] && [ "$failed" -eq 0 ]; then
	fail "4 go test exited $status"
fi

echo
echo "============================================"
echo "   TEST SUMMARY"
echo "============================================"
echo
echo "Total Tests: $total"
echo "Passed:      $passed"
echo "Failed:      $failed"
echo "Skipped:     $skipped"
echo
if [ "$failed" -gt 0 ]; then
	echo "${red}FAILURES DETECTED${reset}"
	exit 1
fi
echo "${green}All tests passed!${reset}"
exit 0
