# Email Security Checker

A Bash script that audits a domain's email security: SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, BIMI and CAA. It scores the setup, explains each problem, and suggests the exact DNS records to fix it.

## Features

- **MX**: null MX (RFC 7505), CNAME targets, missing A/AAAA records, IPv6-only hosts, forward-confirmed reverse DNS (PTR), blocklist lookups (Spamhaus ZEN, SpamCop), and STARTTLS on port 25 (certificate validity, expiry, TLS version)
- **SPF**: duplicate records, the `all` qualifier (`-all` / `~all` / `?all` / `+all`, following `redirect=`), the 10-DNS-lookup limit (counted recursively), broken `include:`/`redirect=` targets and the deprecated `ptr` mechanism
- **DKIM**: 40+ common selectors queried in parallel plus your own (`-s`), RSA key size (via `openssl`), Ed25519 keys, revoked keys and testing mode
- **DMARC**: duplicate records, policy strength (`reject` > `quarantine` > `none`), `pct`, `sp=none`, reporting (`rua`), alignment, and fallback to the organizational domain for subdomains
- **DNSSEC**: DS record at the parent, DNSKEY, and real validation through the AD flag (detects broken chains)
- **MTA-STS**: policy file fetched over HTTPS, `mode`, `max_age`, and whether every MX host is covered by the policy's `mx:` lines
- **TLS-RPT**: record and report destination
- **BIMI**: logo URL is HTTPS and an SVG, mark certificate (`a=`), and the DMARC enforcement BIMI requires
- **CAA**: issuing CAs (inherited from parent domains), `iodef`

DNS failures (SERVFAIL or timeout) are reported as "lookup failed" and left out of the score, so a resolver problem doesn't look like a missing record.

## Prerequisites

- Bash 4.4 or newer (macOS ships 3.2: `brew install bash`)
- `dig`, `curl`, `openssl`

```bash
sudo apt install dnsutils curl openssl      # Ubuntu/Debian/Kali
sudo dnf install bind-utils curl openssl    # RHEL/Fedora
brew install bash bind curl openssl         # macOS
```

## Usage

```bash
git clone https://github.com/fawad0x0/email_security_checker.git
cd email_security_checker
chmod +x email_security_checker.sh

./email_security_checker.sh example.com
```

With no domain, the script asks for one interactively.

```text
Usage: email_security_checker.sh [options] [domain ...]

Options:
  -d, --domain DOMAIN     Domain to check (repeatable; positional args also work)
  -f, --file FILE         Read domains from FILE, one per line ('-' for stdin)
  -s, --selector NAME     Extra DKIM selector to try (repeatable)
  -o, --output FILE       Write the text report to FILE (default: auto-named per domain)
      --no-report         Don't write a text report file
      --json              Print results as JSON (one object per line per domain)
      --no-color          Disable coloured output (also honours NO_COLOR)
  -q, --quiet             Only print the summary line per domain
      --fail-under N      Exit with status 1 if any domain scores below N (0-100)
      --resolver IP       DNS resolver to query (default: system resolver)
      --skip-tls          Skip live TLS probes (SMTP STARTTLS, HTTPS certificate issuer)
  -h, --help              Show this help
  -V, --version           Show version
```

Exit status: `0` success, `1` a score is below `--fail-under`, `2` usage, dependency or invalid-domain error.

### Examples

```bash
# Check a domain that signs with a custom DKIM selector
./email_security_checker.sh -s mycompany2024 example.com

# Check many domains, one summary line each
./email_security_checker.sh -q -f domains.txt --no-report

# JSON for dashboards or scripts
./email_security_checker.sh --json example.com | jq '.score, .fixes'

# Fail a CI job when the score drops below 80
./email_security_checker.sh --no-report --fail-under 80 example.com
```

The domain can also be given as a URL or an email address (`https://Example.com/`, `user@example.com`).

### Notes

- **DKIM selectors** can't be listed from DNS. If no key is found on the common selectors, the result is "unknown", not "missing". Look up `s=` in the `DKIM-Signature` header of a message you sent, and pass it with `-s`.
- **Port 25** is blocked by many ISPs and cloud providers. If it's unreachable, the STARTTLS probe is skipped with a note and the score isn't affected.
- **Blocklists**: Spamhaus refuses queries from public resolvers (8.8.8.8, 1.1.1.1). Use `--resolver` with your own resolver for accurate results.

## Scoring

| Check   | Points |
|---------|-------:|
| SPF     |     20 |
| DKIM    |     20 |
| DMARC   |     20 |
| MX      |     15 |
| DNSSEC  |     10 |
| MTA-STS |      5 |
| CAA     |      5 |
| TLS-RPT |      3 |
| BIMI    |      2 |

Checks earn partial credit. For example, SPF `~all` earns 16 of 20 points and `-all` earns 20, and DMARC `p=none` earns 5 of 20 points and `p=reject` earns 20. Checks that don't apply (for example MTA-STS on a domain with a null MX) or whose lookups failed are left out of the total. Grades: 90%+ Excellent, 75%+ Good, 50%+ Fair, otherwise Poor.

## Recommended fixes

Fixes are printed at the end and included in the report and JSON output. Where possible they are tailored to the domain:

- The SPF `include:` and the DKIM setup steps are based on the mail provider detected from the MX records (Google Workspace, Microsoft 365, Zoho, Proton, Fastmail, Mimecast, GoDaddy).
- DMARC changes keep the existing tags and move the policy one step at a time (`none` → `quarantine` → `reject`).
- The MTA-STS policy file lists the domain's actual MX hosts.
- The CAA record names the CA that currently issues the domain's HTTPS certificate.

## Development

The tests run offline. They put a fake `dig` and `curl` on `PATH` that answer from [tests/fixtures](tests/fixtures).

```bash
bash tests/run_tests.sh
shellcheck -x email_security_checker.sh tests/run_tests.sh tests/bin/*
```

GitHub Actions runs both on every push and pull request, plus a non-blocking check against a real domain.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
