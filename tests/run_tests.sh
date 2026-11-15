#!/usr/bin/env bash
# Offline tests: runs the checker against fixture DNS/HTTP data via fake dig and curl.

set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$here/../email_security_checker.sh"
export PATH="$here/bin:$PATH"
export FAKE_ZONE="$here/fixtures/zone.txt"
export FAKE_HTTP="$here/fixtures/http"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0
failed=0

# Runs the checker with ARGS, storing stdout in $out and the exit code in $rc.
run() {
    out=$(bash "$script" --skip-tls --no-color "$@" 2> "$tmp/stderr")
    rc=$?
}

ok() {
    passed=$((passed + 1))
    echo "  ok   $1"
}

not_ok() {
    failed=$((failed + 1))
    echo "  FAIL $1"
    [[ -n ${2:-} ]] && echo "       $2"
}

expect_contains() {  # DESCRIPTION NEEDLE
    if grep -qF -- "$2" <<< "$out"; then ok "$1"; else not_ok "$1" "missing: $2"; fi
}

expect_not_contains() {  # DESCRIPTION NEEDLE
    if grep -qF -- "$2" <<< "$out"; then not_ok "$1" "unexpected: $2"; else ok "$1"; fi
}

expect_rc() {  # DESCRIPTION CODE
    if [[ $rc == "$2" ]]; then ok "$1"; else not_ok "$1" "exit code $rc, expected $2"; fi
}

echo "good.example (fully configured)"
run --json good.example
expect_rc "exits 0" 0
expect_contains "scores 100" '"score":100,'
expect_contains "SPF passes" '"SPF":{"status":"pass","points":20'
expect_contains "DKIM 2048-bit key from split TXT strings" "Selector 'google': 2048-bit RSA key"
expect_contains "DNSSEC validated" '"DNSSEC":{"status":"pass"'
expect_contains "MTA-STS enforce with all MX covered" '"MTA-STS":{"status":"pass"'
expect_contains "BIMI logo fetched" "Logo is an SVG"
expect_contains "detects Google Workspace" "Mail provider: Google Workspace"
expect_contains "no fixes needed" '"fixes":[]}'
expect_not_contains "no broken SPF includes" "has no SPF record"

echo "bad.example (weak configuration)"
run --json bad.example
expect_contains "redirect target parsed without trailing quote" '"SPF":{"status":"partial","points":16'
expect_not_contains "redirect not reported broken" "has no SPF record"
expect_contains "DKIM key without v=DKIM1 is found" "Selector 's1': 1024-bit RSA key"
expect_contains "sp=none does not hide p=none" "Policy p=none only monitors"
expect_contains "missing rua flagged" "No aggregate reports"
expect_contains "DMARC fix keeps sp and raises p" 'v=DMARC1; sp=none; p=quarantine'
expect_contains "CNAME MX flagged" "mail.bad.example is a CNAME"
expect_contains "MX without address flagged" "MX mx2.bad.example has no A or AAAA record"
expect_contains "missing PTR flagged" "has no reverse DNS"
expect_contains "RBL listing flagged" "listed on zen.spamhaus.org"
expect_contains "DNSSEC missing" '"DNSSEC":{"status":"fail"'
expect_contains "MTA-STS fix lists the real MX hosts" 'mx: mail.bad.example\nmx: mx2.bad.example'
expect_contains "generic SPF placeholder when provider unknown" "~all"

run --fail-under 90 -q bad.example
expect_rc "--fail-under returns 1 below threshold" 1
expect_contains "quiet mode prints one summary line" "bad.example: "

echo "nullmx.example (non-mail domain)"
run --json nullmx.example
expect_contains "null MX recognised" "Null MX (RFC 7505)"
expect_contains "DKIM not applicable" '"DKIM":{"status":"n/a"'
expect_contains "MTA-STS not applicable" '"MTA-STS":{"status":"n/a"'

echo "multi.example (duplicate records)"
run --json multi.example
expect_contains "multiple SPF records fail" "2 SPF records published"
expect_contains "multiple DMARC records fail" "2 DMARC records"

echo "lookups.example (SPF lookup limit)"
run --json lookups.example
expect_contains "more than 10 lookups flagged" "11 DNS lookups - exceeds the limit of 10"
expect_contains "SPF capped at 5 points" '"SPF":{"status":"partial","points":5'

echo "sub.good.example (organizational domain fallback)"
run --json sub.good.example
expect_contains "DMARC inherited from parent" "Inherited from organizational domain good.example"
expect_contains "CAA inherited from parent" "Inherited from good.example"

echo "servfail.example (resolver failures)"
run --json servfail.example
expect_contains "SPF reported as lookup error" '"SPF":{"status":"error"'
expect_contains "DKIM reported as lookup error" '"DKIM":{"status":"error"'
expect_contains "score is unknown, not 0% failure" '"grade":"Unknown"'

echo "command line"
run --json "https://Good.Example./path"
expect_contains "normalises URL, case and trailing dot" '"domain":"good.example"'
run --json user@good.example
expect_contains "accepts an email address" '"domain":"good.example"'
run --no-report "bad..example"
expect_rc "rejects empty labels" 2
run --no-report "-bad.example"
expect_rc "rejects unknown options" 2
run --no-report "x.xn--p1ai" --json
expect_contains "accepts punycode TLDs" '"domain":"x.xn--p1ai"'
run -o "$tmp/report.txt" good.example nullmx.example
expect_rc "checks several domains" 0
out=$(cat "$tmp/report.txt")
expect_contains "report has first domain" "Email Security Report for good.example"
expect_contains "report has second domain" "Email Security Report for nullmx.example"
expect_contains "report contains fixes section" "=== Recommended DNS Fixes ==="
printf 'good.example\n# comment\n\nnullmx.example\n' > "$tmp/domains.txt"
run -q -f "$tmp/domains.txt" --no-report
expect_contains "reads domains from file" "nullmx.example: "

echo
echo "$passed passed, $failed failed"
(( failed == 0 ))
