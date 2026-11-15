#!/usr/bin/env bash
#
# Email Security Checker
# Audits a domain's email authentication and transport security
# (MX, SPF, DKIM, DMARC, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA),
# scores the result and suggests DNS fixes.

set -uo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "Bash 4.4 or newer is required (macOS: brew install bash)." >&2
    exit 2
fi

readonly VERSION="2.0.0"

# --- Configuration --- #

# Weighted scoring (points per check)
declare -A weights=(
    [MX]=15
    [SPF]=20
    [DKIM]=20
    [DMARC]=20
    [DNSSEC]=10
    [MTA-STS]=5
    [TLS-RPT]=3
    [BIMI]=2
    [CAA]=5
)
CHECK_ORDER=(MX SPF DKIM DMARC DNSSEC MTA-STS TLS-RPT BIMI CAA)

# Common DKIM selectors (Google, Microsoft 365, ESPs, hosting providers)
DKIM_SELECTORS=(
    google 20230601 20221208 20220809 20210223 20210112 20161025 krs
    selector1 selector2 s1 s2 k1 k2 k3 mx dkim domainkey default key1 key2
    signer em mail smtp email zoho zmail protonmail protonmail2 protonmail3
    fm1 fm2 fm3 mandrill everlytickey1 everlytickey2 mailjet smtpapi
    phishprotection sig1 dk cm
)

# DNS blocklists checked for MX addresses
RBL_ZONES=(zen.spamhaus.org bl.spamcop.net)

# --- Options --- #

domains=()
selectors=()
output_path=""
write_reports=true
json_mode=false
quiet=false
use_color=auto
fail_under=""
resolver=""
skip_tls=false

# --- Per-domain state --- #

domain=""
report_file=""
current_check=""
start_time=0
last_score=0
declare -A c_status=() c_points=() c_records=() c_findings=()
fixes=()
mx_hosts=()
null_mx=false
provider="" provider_spf="" provider_dkim=""
spf_record=""
dmarc_policy=""
rbl_refused_noted=false
declare -A spf_seen=()
spf_lookups=0
spf_broken=()

US=$'\x1f'  # field separator for stored findings and fixes
output_initialized=false

usage() {
    cat <<EOF
Email Security Checker v$VERSION

Usage: ${0##*/} [options] [domain ...]

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

Exit status: 0 success, 1 score below --fail-under, 2 usage, dependency or domain error.
EOF
}

die_usage() {
    echo "Error: $*" >&2
    echo "Try '${0##*/} --help' for more information." >&2
    exit 2
}

need_arg() {
    [[ $# -ge 2 && -n $2 ]] || die_usage "Option $1 requires an argument"
}

trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

read_domain_file() {
    local src=$1 line
    [[ $src == - ]] && src=/dev/stdin
    [[ -r $src ]] || die_usage "Cannot read domain file: $1"
    while IFS= read -r line || [[ -n $line ]]; do
        line=$(trim "${line%%#*}")
        [[ -n $line ]] && domains+=("$line")
    done < "$src"
}

parse_args() {
    while (( $# )); do
        case $1 in
            -d|--domain)   need_arg "$@"; domains+=("$2"); shift 2 ;;
            -f|--file)     need_arg "$@"; read_domain_file "$2"; shift 2 ;;
            -s|--selector) need_arg "$@"; selectors+=("$2"); shift 2 ;;
            -o|--output)   need_arg "$@"; output_path=$2; shift 2 ;;
            --no-report)   write_reports=false; shift ;;
            --json)        json_mode=true; shift ;;
            --no-color)    use_color=never; shift ;;
            -q|--quiet)    quiet=true; shift ;;
            --fail-under)  need_arg "$@"; fail_under=$2; shift 2 ;;
            --resolver)    need_arg "$@"; resolver=$2; shift 2 ;;
            --skip-tls)    skip_tls=true; shift ;;
            -h|--help)     usage; exit 0 ;;
            -V|--version)  echo "$VERSION"; exit 0 ;;
            --)            shift; domains+=("$@"); break ;;
            -*)            die_usage "Unknown option: $1" ;;
            *)             domains+=("$1"); shift ;;
        esac
    done

    if [[ -n $fail_under ]] && ! [[ $fail_under =~ ^[0-9]+$ && $fail_under -le 100 ]]; then
        die_usage "--fail-under must be a number between 0 and 100"
    fi
    local sel
    for sel in "${selectors[@]}"; do
        [[ $sel =~ ^[A-Za-z0-9._-]+$ ]] || die_usage "Invalid DKIM selector: $sel"
    done
}

setup_colors() {
    if [[ $use_color != never ]] && ! $json_mode && [[ -t 1 && -z ${NO_COLOR:-} ]]; then
        RED=$'\033[0;31m'
        GREEN=$'\033[0;32m'
        YELLOW=$'\033[1;33m'
        CYAN=$'\033[0;36m'
        BOLD=$'\033[1m'
        NC=$'\033[0m'
    else
        RED="" GREEN="" YELLOW="" CYAN="" BOLD="" NC=""
    fi
}

# Dependency Check
check_deps() {
    local missing=() cmd
    for cmd in dig curl openssl awk sed sort; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    (( ${#missing[@]} == 0 )) && return

    echo "${RED}Missing dependencies: ${missing[*]}${NC}" >&2
    if command -v apt-get >/dev/null 2>&1; then
        echo "Install with: sudo apt-get install -y dnsutils curl openssl" >&2
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        echo "Install with: sudo dnf install -y bind-utils curl openssl" >&2
    elif command -v apk >/dev/null 2>&1; then
        echo "Install with: sudo apk add bind-tools curl openssl" >&2
    elif command -v pacman >/dev/null 2>&1; then
        echo "Install with: sudo pacman -S bind curl openssl" >&2
    elif command -v brew >/dev/null 2>&1; then
        echo "Install with: brew install bind curl openssl" >&2
    fi
    exit 2
}

TIMEOUT_CMD=()
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(timeout)
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(gtimeout)
fi

with_timeout() {
    local secs=$1
    shift
    if (( ${#TIMEOUT_CMD[@]} )); then
        "${TIMEOUT_CMD[@]}" "$secs" "$@"
    else
        "$@"
    fi
}

# --- DNS helpers --- #

dig_opts=()

# Queries NAME/TYPE and prints the rdata of matching answers, one per line.
# Returns 0 on NOERROR (answers may be empty), 1 on NXDOMAIN, 2 on resolver failure.
dns() {
    local type=$1 name=$2 raw status
    raw=$(dig "${dig_opts[@]}" +noall +comments +answer "$name" "$type" 2>/dev/null) || return 2
    status=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<< "$raw" | head -n 1)
    case $status in
        NOERROR) ;;
        NXDOMAIN) return 1 ;;
        *) return 2 ;;
    esac
    awk -v t="$type" '
        /^;/ || NF < 5 { next }
        toupper($4) == toupper(t) {
            sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]+[^ \t]+[ \t]+/, "")
            print
        }' <<< "$raw"
}

# Prints each TXT record at NAME with its character-strings joined, one per line.
txt_records() {
    local out rc
    out=$(dns TXT "$1")
    rc=$?
    [[ -n $out ]] && sed -E -e 's/"[[:space:]]+"//g' -e 's/^"//' -e 's/"$//' <<< "$out"
    return $rc
}

# Returns 0 if the resolver sets the AD (authenticated data) flag for NAME,
# 1 if it answers without it, 2 if it fails (SERVFAIL means bogus on a validating resolver).
dns_authenticated() {
    local name=$1 server=${2:-} raw
    local -a opts=("${dig_opts[@]}")
    [[ -n $server ]] && opts=("@$server" +time=2 +tries=2)
    raw=$(dig "${opts[@]}" +dnssec +adflag +noall +comments "$name" SOA 2>/dev/null) || return 2
    grep -q 'status: NOERROR' <<< "$raw" || return 2
    grep -Eq '^;; flags:[^;]* ad[ ;]' <<< "$raw"
}

reverse_ip() {
    local IFS=.
    local -a o
    read -ra o <<< "$1"
    printf '%s.%s.%s.%s' "${o[3]}" "${o[2]}" "${o[1]}" "${o[0]}"
}

# Parses "k=v; k2=v2" tag lists (DKIM, DMARC, BIMI, TLS-RPT) into the named associative array.
parse_tags() {
    local -n _tags=$1
    local part key
    local -a parts
    _tags=()
    IFS=';' read -ra parts <<< "$2"
    for part in "${parts[@]}"; do
        [[ $part == *=* ]] || continue
        key=$(trim "${part%%=*}")
        _tags[${key,,}]=$(trim "${part#*=}")
    done
}

# --- Output and report handling --- #

say() {
    $quiet || $json_mode || printf '%s\n' "$1"
}

report() {
    [[ -n $report_file ]] && printf '%s\n' "$1" >> "$report_file"
    return 0
}

init_report() {
    report_file=""
    if [[ -n $output_path ]]; then
        report_file=$output_path
        if ! $output_initialized; then
            : > "$report_file"
            output_initialized=true
        fi
    elif $write_reports && ! $json_mode; then
        report_file="email_security_report_${domain}_$(date +"%Y%m%d_%H%M%S").txt"
        : > "$report_file"
    fi
    report "=== Email Security Report for ${domain} ==="
    report "Generated on: $(date)"
    report "Resolver: ${resolver:-system default}"
    report "=========================================="
}

section() {
    current_check=$1
    say ""
    say "${BOLD}${CYAN}=== $1 ===${NC}"
    report ""
    report "=== $1 ==="
}

# Records a finding: LEVEL is pass, warn, fail or info.
emit() {
    local level=$1 msg=$2 icon color
    case $level in
        pass) icon="✅" color=$GREEN ;;
        warn) icon="⚠️ " color=$YELLOW ;;
        fail) icon="❌" color=$RED ;;
        *)    icon="ℹ️ " color=$CYAN ;;
    esac
    c_findings[$current_check]+="${level}${US}${msg}"$'\n'
    say "${color}${icon} ${msg}${NC}"
    report "[${level^^}] $msg"
}

record() {
    c_records[$current_check]+="$1"$'\n'
    say "   Record: $1"
    report "Record: $1"
}

# Stores the check result. STATUS defaults to pass/partial/fail derived from POINTS;
# "error" (lookup failed) and "n/a" (not applicable) are excluded from the total.
finish() {
    local points=$1 status=${2:-} max=${weights[$current_check]}
    (( points < 0 )) && points=0
    (( points > max )) && points=$max
    if [[ -z $status ]]; then
        if (( points == max )); then status=pass
        elif (( points == 0 )); then status=fail
        else status=partial; fi
    fi
    c_status[$current_check]=$status
    c_points[$current_check]=$points
    case $status in
        error) say "${YELLOW}   Score: n/a (lookup failed, excluded from total)${NC}"
               report "Score: n/a (lookup failed)" ;;
        n/a)   say "   Score: n/a (not applicable)"
               report "Score: n/a (not applicable)" ;;
        *)     say "   Score: $points/$max"
               report "Score: $points/$max ($status)" ;;
    esac
}

dns_error() {
    emit warn "DNS lookup for $1 failed (SERVFAIL or timeout) - check skipped"
    finish 0 error
}

# Queues a recommended fix: CHECK ADVICE [TYPE HOST VALUE]
fix() {
    fixes+=("$1${US}$2${US}${3:-}${US}${4:-}${US}${5:-}")
}

# --- Domain handling --- #

normalize_domain() {
    local d
    d=$(trim "${1,,}")
    d=${d#*://}
    d=${d##*@}
    d=${d%%/*}
    d=${d%.}
    printf '%s' "$d"
}

valid_domain() {
    (( ${#1} <= 253 )) &&
        [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$ ]]
}

# Sets provider, provider_spf and provider_dkim from well-known MX hosts.
detect_provider() {
    local h
    provider="" provider_spf="" provider_dkim=""
    for h in "${mx_hosts[@]}"; do
        case $h in
            *.google.com|*.googlemail.com)
                provider="Google Workspace"
                provider_spf="include:_spf.google.com"
                provider_dkim="Admin console > Apps > Google Workspace > Gmail > Authenticate email" ;;
            *.mail.protection.outlook.com)
                provider="Microsoft 365"
                provider_spf="include:spf.protection.outlook.com"
                provider_dkim="Microsoft Defender portal > Email authentication settings > DKIM (publishes selector1/selector2 CNAMEs)" ;;
            *.zoho.com|*.zoho.eu|*.zoho.in)
                provider="Zoho Mail"
                provider_spf="include:zoho.${h##*.}"
                provider_dkim="Zoho Mail Admin Console > Domains > Email Configuration > DKIM" ;;
            *.protonmail.ch)
                provider="Proton Mail"
                provider_spf="include:_spf.protonmail.ch"
                provider_dkim="Proton settings > Domain names > DKIM (CNAMEs protonmail, protonmail2, protonmail3)" ;;
            *.messagingengine.com)
                provider="Fastmail"
                provider_spf="include:spf.messagingengine.com"
                provider_dkim="Fastmail Settings > Domains (CNAMEs fm1, fm2, fm3)" ;;
            *.mimecast.com)
                provider="Mimecast"
                provider_spf="include:_netblocks.mimecast.com"
                provider_dkim="Mimecast Administration > Gateway > Policies > DNS Authentication - Outbound" ;;
            *.secureserver.net)
                provider="GoDaddy"
                provider_spf="include:secureserver.net"
                provider_dkim="your GoDaddy email settings" ;;
        esac
        [[ -n $provider ]] && return
    done
}

# --- Core Checks --- #

check_ptr() {
    local host=$1 ip=$2 ptr
    ptr=$(dns PTR "$(reverse_ip "$ip").in-addr.arpa" | head -n 1)
    ptr=${ptr%.}
    if [[ -z $ptr ]]; then
        emit warn "$host ($ip) has no reverse DNS (PTR) - many receivers distrust such servers"
        return 1
    fi
    if ! dns A "$ptr" | grep -qxF "$ip"; then
        emit warn "$host ($ip) PTR $ptr does not resolve back to $ip"
        return 1
    fi
    emit pass "$host ($ip) reverse DNS: $ptr"
}

# Returns 1 if IP is listed on any blocklist.
check_rbl() {
    local ip=$1 rev zone ans clean=0
    rev=$(reverse_ip "$ip")
    for zone in "${RBL_ZONES[@]}"; do
        ans=$(dns A "$rev.$zone" | head -n 1)
        case $ans in
            '') ;;
            127.255.255.*)
                if ! $rbl_refused_noted; then
                    emit info "$zone refused the query (public resolvers are blocked) - use --resolver with your own resolver"
                    rbl_refused_noted=true
                fi ;;
            127.*)
                emit fail "HIGH: $ip is listed on $zone ($ans) - mail from it is likely rejected"
                clean=1 ;;
        esac
    done
    return $clean
}

# Returns 0 if HOST offers STARTTLS with a valid certificate,
# 1 if TLS is missing or weak, 2 if port 25 is unreachable.
check_starttls() {
    local host=$1 out cert proto verify enddate
    out=$(with_timeout 20 openssl s_client -starttls smtp -connect "$host:25" \
        -servername "$host" -verify_hostname "$host" < /dev/null 2>&1)
    grep -q '^CONNECTED' <<< "$out" || return 2

    cert=$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' <<< "$out")
    if [[ -z $cert ]]; then
        emit fail "MEDIUM: $host does not offer STARTTLS - mail to it travels unencrypted"
        return 1
    fi
    proto=$(grep -m 1 -oE 'TLSv1(\.[0-3])?' <<< "$out")
    verify=$(sed -n 's/^ *Verify return code: //p' <<< "$out" | tail -n 1)
    enddate=$(openssl x509 -noout -enddate <<< "$cert" 2>/dev/null)
    enddate=${enddate#notAfter=}

    local ok=0
    if [[ $verify != 0* ]]; then
        emit warn "$host: STARTTLS ${proto:-} certificate failed verification: ${verify:-unknown error}"
        ok=1
    elif ! openssl x509 -noout -checkend 1209600 <<< "$cert" >/dev/null 2>&1; then
        emit warn "$host: certificate expires soon ($enddate)"
        ok=1
    else
        emit pass "$host: STARTTLS ${proto:-} with a valid certificate (expires $enddate)"
    fi
    if [[ $proto == TLSv1 || $proto == TLSv1.1 ]]; then
        emit warn "$host negotiated obsolete $proto - enable TLS 1.2 or newer"
        ok=1
    fi
    return $ok
}

check_mx() {
    section MX
    local out rc pref host points=15
    out=$(dns MX "$domain")
    rc=$?
    (( rc == 2 )) && { dns_error "$domain MX"; return; }

    if [[ -z $out ]]; then
        emit fail "HIGH: No MX records - senders fall back to the A record, or mail bounces"
        fix MX "If $domain should not receive email, publish a null MX (RFC 7505); otherwise add the MX records from your mail provider" \
            MX "$domain" "0 ."
        finish 0
        return
    fi

    out=$(sort -n <<< "$out")
    if [[ $(grep -c . <<< "$out") -eq 1 && $(awk '{print $2}' <<< "$out") == "." ]]; then
        record "$out"
        emit info "Null MX (RFC 7505): $domain declares that it does not receive email"
        null_mx=true
        finish 15
        return
    fi

    while read -r pref host; do
        host=${host%.}
        record "$pref ${host,,}"
        mx_hosts+=("${host,,}")
    done <<< "$out"
    detect_provider
    [[ -n $provider ]] && emit info "Mail provider: $provider"

    local a aaaa ip unresolved=0 cnames=0 no_ptr=0 listed=0 tls_bad=0
    local -a reachable=()
    for host in "${mx_hosts[@]}"; do
        if [[ -n $(dns CNAME "$host") ]]; then
            emit warn "$host is a CNAME - MX targets must be A/AAAA names (RFC 2181 §10.3)"
            ((cnames++))
        fi
        a=$(dns A "$host")
        aaaa=$(dns AAAA "$host")
        if [[ -z $a && -z $aaaa ]]; then
            emit fail "HIGH: MX $host has no A or AAAA record - it cannot receive mail"
            ((unresolved++))
            continue
        fi
        reachable+=("$host")
        [[ -z $a ]] && emit info "$host is IPv6-only - IPv4-only senders cannot reach it"
        for ip in $a; do
            check_ptr "$host" "$ip" || ((no_ptr++))
            check_rbl "$ip" || ((listed++))
        done
    done

    if (( unresolved == ${#mx_hosts[@]} )); then
        finish 0
        return
    fi
    (( unresolved )) && points=$((points - 6))
    (( cnames )) && points=$((points - 2))
    (( no_ptr )) && points=$((points - 2))
    (( listed )) && points=$((points - 4))

    if ! $skip_tls; then
        for host in "${reachable[@]}"; do
            check_starttls "$host"
            case $? in
                1) ((tls_bad++)) ;;
                2) emit info "Port 25 is unreachable from this network - STARTTLS probes skipped (outbound SMTP is often blocked)"
                   break ;;
            esac
        done
        (( tls_bad )) && points=$((points - 4))
    fi
    finish "$points"
}

# Recursively counts DNS-querying SPF terms (RFC 7208 §4.6.4 limit: 10).
spf_walk() {
    local name=$1 depth=$2 rec=${3:-} term target
    (( depth > 10 )) && return
    [[ -n ${spf_seen[$name]:-} ]] && return
    spf_seen[$name]=1
    if [[ -z $rec ]]; then
        rec=$(txt_records "$name" | grep -Ei '^v=spf1( |$)' | head -n 1)
        [[ -z $rec ]] && { spf_broken+=("$name"); return; }
    fi
    local -a terms
    read -ra terms <<< "${rec,,}"
    for term in "${terms[@]}"; do
        term=${term#[-+~?]}
        case $term in
            include:*|redirect=*)
                spf_lookups=$((spf_lookups + 1))
                target=${term#*[:=]}
                [[ $target == *%* ]] || spf_walk "$target" $((depth + 1)) ;;
            a|a[:/]*|mx|mx[:/]*|ptr|ptr:*|exists:*)
                spf_lookups=$((spf_lookups + 1)) ;;
        esac
    done
}

# Prints the qualifier (- ~ ? +) of the effective 'all', following redirect= when there is none.
spf_all_qualifier() {
    local rec=$1 depth=$2 term redirect=""
    local -a terms
    read -ra terms <<< "${rec,,}"
    for term in "${terms[@]}"; do
        case $term in
            all|+all) echo "+"; return ;;
            -all|'~all'|'?all') echo "${term:0:1}"; return ;;
            redirect=*) redirect=${term#redirect=} ;;
        esac
    done
    if [[ -n $redirect ]] && (( depth < 5 )); then
        spf_all_qualifier "$(txt_records "$redirect" | grep -Ei '^v=spf1( |$)' | head -n 1)" $((depth + 1))
    fi
}

check_spf() {
    section SPF
    local records rc spf count r points
    local suggested="v=spf1 ${provider_spf:-include:<your-mail-provider>} ~all"
    $null_mx && suggested="v=spf1 -all"

    records=$(txt_records "$domain")
    rc=$?
    (( rc == 2 )) && { dns_error "$domain TXT"; return; }
    spf=$(grep -Ei '^v=spf1( |$)' <<< "$records")
    count=$(grep -c . <<< "$spf")

    if (( count == 0 )); then
        emit fail "HIGH: No SPF record - anyone can send mail claiming to be $domain"
        fix SPF "Add an SPF record listing every service that sends mail as $domain" TXT "$domain" "$suggested"
        finish 0
        return
    fi
    if (( count > 1 )); then
        while IFS= read -r r; do record "$r"; done <<< "$spf"
        emit fail "HIGH: $count SPF records published - receivers treat this as a permanent error (RFC 7208 §3.2)"
        fix SPF "Merge all SPF records into a single TXT record"
        finish 0
        return
    fi
    record "$spf"
    spf_record=$spf

    [[ ${spf,,} =~ (^|[[:space:]])[-+~?]?ptr([:[:space:]]|$) ]] &&
        emit warn "The 'ptr' mechanism is deprecated and slow (RFC 7208 §5.5)"

    spf_seen=()
    spf_lookups=0
    spf_broken=()
    spf_walk "$domain" 0 "$spf"
    if (( spf_lookups > 10 )); then
        emit fail "HIGH: $spf_lookups DNS lookups - exceeds the limit of 10, SPF will fail with permerror"
        fix SPF "Reduce SPF DNS lookups to 10 or fewer: remove unused include: terms, or replace them with ip4:/ip6: ranges"
    else
        emit pass "$spf_lookups/10 DNS lookups used"
    fi
    for r in "${spf_broken[@]}"; do
        emit warn "include/redirect target $r has no SPF record (permerror)"
        fix SPF "Remove or correct the SPF reference to $r"
    done

    case $(spf_all_qualifier "$spf" 0) in
        -)  emit pass "Ends in -all (hard fail for unauthorised senders)"
            points=20 ;;
        '~') emit info "Ends in ~all (soft fail) - consider -all once all senders are covered"
            points=16
            fix SPF "Once DMARC reports show all legitimate senders pass, tighten ~all to -all" ;;
        '?') emit warn "MEDIUM: ?all (neutral) gives no protection"
            points=6
            fix SPF "Replace ?all with ~all, then -all" ;;
        +)  emit fail "HIGH: +all authorises every server on the internet to send as $domain"
            points=0
            fix SPF "Replace +all with ~all (or -all) immediately" ;;
        *)  emit warn "MEDIUM: No 'all' mechanism - unlisted senders default to neutral"
            points=6
            fix SPF "End the SPF record with ~all (or -all)" ;;
    esac
    (( spf_lookups > 10 && points > 5 )) && points=5
    (( ${#spf_broken[@]} )) && points=$((points - 5))
    finish "$points"
}

# Prints the size in bits of a base64 DER public key.
rsa_key_bits() {
    printf '%s' "$1" | openssl base64 -d -A 2>/dev/null |
        openssl pkey -pubin -inform DER -noout -text 2>/dev/null |
        grep -oE '[0-9]+ bit' | head -n 1 | grep -oE '[0-9]+'
}

check_dkim() {
    section DKIM
    local -a sels=()
    local -A seen=()
    local sel i tmp
    for sel in "${selectors[@]}" "${DKIM_SELECTORS[@]}"; do
        [[ -n ${seen[$sel]:-} ]] && continue
        seen[$sel]=1
        sels+=("$sel")
    done

    if $null_mx && [[ ${spf_record,,} == "v=spf1 -all" ]]; then
        emit info "Domain neither sends nor receives mail (null MX, SPF -all) - DKIM not needed"
        finish 0 n/a
        return
    fi

    tmp=$(mktemp -d) || { emit warn "Could not create a temp directory"; finish 0 error; return; }
    for i in "${!sels[@]}"; do
        { txt_records "${sels[i]}._domainkey.$domain" > "$tmp/$i"; echo $? > "$tmp/$i.rc"; } &
    done
    wait

    local found=0 errors=0 best=0 score rec bits
    local -A tags=()
    for i in "${!sels[@]}"; do
        sel=${sels[i]}
        [[ $(< "$tmp/$i.rc") == 2 ]] && { ((errors++)); continue; }
        rec=$(grep -E '(^|;)[[:space:]]*p=' "$tmp/$i" | head -n 1)
        [[ -z $rec ]] && continue
        ((found++))
        record "$sel: ${rec:0:100}$( (( ${#rec} > 100 )) && echo '...')"
        parse_tags tags "$rec"
        local p=${tags[p]:-}
        p=${p//[[:space:]]/}
        if [[ -z $p ]]; then
            emit warn "Selector '$sel' key is revoked (empty p=)"
            continue
        fi
        if [[ ${tags[k]:-rsa} == ed25519 ]]; then
            emit pass "Selector '$sel': Ed25519 key"
            score=20
        else
            bits=$(rsa_key_bits "$p")
            if [[ -z $bits ]]; then
                emit warn "Selector '$sel': could not decode the public key"
                score=15
            elif (( bits >= 2048 )); then
                emit pass "Selector '$sel': $bits-bit RSA key"
                score=20
            elif (( bits >= 1024 )); then
                emit warn "MEDIUM: Selector '$sel': $bits-bit RSA key is below the recommended 2048 bits"
                fix DKIM "Rotate DKIM selector '$sel' to a 2048-bit RSA key"
                score=12
            else
                emit fail "HIGH: Selector '$sel': $bits-bit RSA key can be cracked"
                fix DKIM "Replace DKIM selector '$sel' with a 2048-bit RSA key now"
                score=5
            fi
        fi
        [[ ${tags[t]:-} == *y* ]] && emit info "Selector '$sel' is in testing mode (t=y)"
        (( score > best )) && best=$score
    done
    rm -rf "$tmp"

    if (( found == 0 )); then
        if (( errors == ${#sels[@]} )); then
            dns_error "DKIM selectors"
            return
        fi
        emit warn "MEDIUM: No DKIM key found on ${#sels[@]} common selectors - DKIM may still use a custom selector"
        emit info "Find the selector in the DKIM-Signature header (s=) of a sent message and re-run with -s SELECTOR"
        if [[ -n $provider_dkim ]]; then
            fix DKIM "Enable DKIM signing in $provider: $provider_dkim"
        else
            fix DKIM "Enable DKIM signing at your mail provider and publish the TXT/CNAME record it gives you (2048-bit key)"
        fi
        finish 0 unknown
        return
    fi
    if (( best == 0 )); then
        fix DKIM "All DKIM keys found are revoked - publish an active 2048-bit key"
    fi
    finish "$best"
}

check_dmarc() {
    section DMARC
    local name="_dmarc.$domain" records rc dmarc count inherited="" parent r points
    local rua_default="mailto:dmarc-reports@$domain"
    records=$(txt_records "$name")
    rc=$?
    (( rc == 2 )) && { dns_error "$name TXT"; return; }
    dmarc=$(grep -E '^v=DMARC1[[:space:]]*(;|$)' <<< "$records")

    # RFC 7489 §6.6.3: fall back to the organizational domain
    if [[ -z $dmarc ]]; then
        parent=$domain
        while [[ $parent == *.*.* ]]; do
            parent=${parent#*.}
            dmarc=$(txt_records "_dmarc.$parent" | grep -E '^v=DMARC1[[:space:]]*(;|$)')
            [[ -n $dmarc ]] && { inherited=$parent; break; }
        done
    fi

    count=$(grep -c . <<< "$dmarc")
    if (( count == 0 )); then
        emit fail "HIGH: No DMARC record - receivers get no policy for spoofed mail and you get no reports"
        if $null_mx; then
            fix DMARC "Reject all mail claiming to be from this non-mail domain" TXT "$name" "v=DMARC1; p=reject;"
        else
            fix DMARC "Start in monitoring mode, review the reports for 2-4 weeks, then move to p=quarantine and p=reject" \
                TXT "$name" "v=DMARC1; p=none; rua=$rua_default"
        fi
        finish 0
        return
    fi
    if (( count > 1 )); then
        while IFS= read -r r; do record "$r"; done <<< "$dmarc"
        emit fail "HIGH: $count DMARC records - receivers ignore DMARC entirely"
        fix DMARC "Keep exactly one DMARC record at $name"
        finish 0
        return
    fi
    record "$dmarc"
    [[ -n $inherited ]] && emit info "Inherited from organizational domain $inherited (sp= applies)"

    local -A tags=()
    parse_tags tags "$dmarc"
    local policy=${tags[p]:-}
    [[ -n $inherited && -n ${tags[sp]:-} ]] && policy=${tags[sp]}
    dmarc_policy=${policy,,}

    local fix_host=$name
    [[ -n $inherited ]] && fix_host="_dmarc.$inherited"
    case $dmarc_policy in
        reject)
            emit pass "Policy: reject"
            points=20 ;;
        quarantine)
            emit pass "Policy: quarantine"
            points=15
            fix DMARC "When reports show no legitimate mail is quarantined, move to p=reject" \
                TXT "$fix_host" "$(sed -E 's/(^|;)([[:space:]]*)p=[A-Za-z]+/\1\2p=reject/' <<< "$dmarc")" ;;
        none)
            emit warn "MEDIUM: Policy p=none only monitors - spoofed mail is still delivered"
            points=5
            fix DMARC "Once reports show legitimate mail passes, enforce the policy (then move to p=reject)" \
                TXT "$fix_host" "$(sed -E 's/(^|;)([[:space:]]*)p=[A-Za-z]+/\1\2p=quarantine/' <<< "$dmarc")" ;;
        *)
            emit fail "HIGH: Missing or invalid p= tag ('$policy') - the record is ignored"
            fix DMARC "Add a valid policy tag" TXT "$fix_host" "v=DMARC1; p=none; rua=$rua_default"
            finish 0
            return ;;
    esac

    local pct=${tags[pct]:-100}
    if [[ $pct =~ ^[0-9]+$ ]] && (( pct < 100 )) && [[ $dmarc_policy != none ]]; then
        emit warn "pct=$pct - the policy only applies to $pct% of failing mail"
        fix DMARC "Raise pct to 100 (or remove it)"
        points=$((points - 3))
    fi
    if [[ -z $inherited && ${tags[sp]:-} == none && $dmarc_policy != none ]]; then
        emit warn "sp=none leaves subdomains open to spoofing"
        fix DMARC "Remove sp=none so subdomains inherit the main policy"
        points=$((points - 3))
    fi
    if [[ ${tags[rua]:-} == *mailto:* ]]; then
        emit pass "Aggregate reports sent to ${tags[rua]}"
    else
        emit warn "No aggregate reports (rua=) - you can't see who sends mail as $domain"
        fix DMARC "Add rua=$rua_default to receive aggregate reports"
        points=$((points - 2))
    fi
    [[ ${tags[adkim]:-r} == s ]] && emit info "Strict DKIM alignment (adkim=s)"
    [[ ${tags[aspf]:-r} == s ]] && emit info "Strict SPF alignment (aspf=s)"
    finish "$points"
}

check_dnssec() {
    section DNSSEC
    local ds dnskey rc ad
    ds=$(dns DS "$domain")
    rc=$?
    (( rc == 2 )) && { dns_error "$domain DS"; return; }
    dnskey=$(dns DNSKEY "$domain")
    dns_authenticated "$domain"
    ad=$?
    if (( ad != 0 )) && [[ -z $resolver ]]; then
        # The system resolver may not validate - confirm with a public validating resolver
        dns_authenticated "$domain" 1.1.1.1
        ad=$?
    fi

    if (( ad == 0 )); then
        [[ -n $ds ]] && emit pass "DS record published at the parent zone"
        emit pass "Answers are DNSSEC-validated (AD flag set)"
        finish 10
    elif (( ad == 2 )) && [[ -n $ds || -n $dnskey ]]; then
        emit fail "HIGH: DNSSEC is broken - validating resolvers return SERVFAIL, so mail to $domain may fail"
        fix DNSSEC "Fix the DS/DNSKEY mismatch at your registrar and DNS host (or remove the DS record first, then disable signing)"
        finish 0
    elif [[ -n $dnskey && -z $ds ]]; then
        emit warn "Zone is signed (DNSKEY) but no DS record at the parent - chain of trust is incomplete"
        fix DNSSEC "Publish the DS record for $domain at your registrar"
        finish 3
    elif [[ -n $ds ]]; then
        emit warn "DS record present, but no validating resolver confirmed the answers"
        finish 5
    else
        emit fail "MEDIUM: DNSSEC not enabled - DNS answers (MX, MTA-STS, DKIM) can be spoofed"
        fix DNSSEC "Enable DNSSEC signing at your DNS host, then publish the DS record at your registrar"
        finish 0
    fi
}

# Matches an MX host against an MTA-STS mx: pattern ("*.example.com" matches one label).
mta_sts_mx_match() {
    local host=$1 pattern=${2,,} suffix prefix
    pattern=${pattern%.}
    if [[ $pattern == \*.* ]]; then
        suffix=${pattern#\*}
        [[ $host == *"$suffix" ]] || return 1
        prefix=${host%"$suffix"}
        [[ -n $prefix && $prefix != *.* ]]
    else
        [[ $host == "$pattern" ]]
    fi
}

mta_sts_policy_text() {
    local mode=$1 h text
    text="version: STSv1"$'\n'"mode: $mode"
    if (( ${#mx_hosts[@]} )); then
        for h in "${mx_hosts[@]}"; do text+=$'\n'"mx: $h"; done
    else
        text+=$'\n'"mx: <your-mx-host>"
    fi
    printf '%s' "$text"$'\n'"max_age: 604800"
}

check_mta_sts() {
    section MTA-STS
    local name="_mta-sts.$domain" records rc rec count policy mode max_age points h p covered
    local url="https://mta-sts.$domain/.well-known/mta-sts.txt"
    local new_id
    new_id="$(date +%Y%m%d)01"

    if $null_mx; then
        emit info "Domain does not receive mail (null MX) - MTA-STS not needed"
        finish 0 n/a
        return
    fi
    records=$(txt_records "$name")
    rc=$?
    (( rc == 2 )) && { dns_error "$name TXT"; return; }
    rec=$(grep -E '^v=STSv1[[:space:]]*(;|$)' <<< "$records")
    count=$(grep -c . <<< "$rec")

    if (( count == 0 )); then
        emit fail "MEDIUM: No MTA-STS record - senders may deliver over unencrypted or downgraded connections"
        fix MTA-STS "Publish the MTA-STS TXT record" TXT "$name" "v=STSv1; id=$new_id"
        fix MTA-STS "Serve this policy at $url (valid HTTPS certificate required); switch to mode: enforce once TLS-RPT reports are clean:"$'\n'"$(mta_sts_policy_text testing)"
        finish 0
        return
    fi
    if (( count > 1 )); then
        emit fail "$count MTA-STS records - senders ignore MTA-STS"
        fix MTA-STS "Keep exactly one MTA-STS record at $name"
        finish 0
        return
    fi
    record "$rec"
    local -A tags=()
    parse_tags tags "$rec"
    [[ -z ${tags[id]:-} ]] && emit warn "Record has no id= tag - senders cannot detect policy changes"

    if ! policy=$(curl -fsS --max-time 10 --proto '=https' --max-filesize 65536 "$url" 2>/dev/null); then
        emit fail "Policy file $url could not be fetched over valid HTTPS"
        fix MTA-STS "Serve the policy file at $url:"$'\n'"$(mta_sts_policy_text testing)"
        finish 1
        return
    fi
    policy=$(tr -d '\r' <<< "$policy")
    if ! grep -qE '^version:[[:space:]]*STSv1[[:space:]]*$' <<< "$policy"; then
        emit fail "Policy file is missing 'version: STSv1'"
        fix MTA-STS "Correct the policy file at $url:"$'\n'"$(mta_sts_policy_text testing)"
        finish 1
        return
    fi
    mode=$(sed -n 's/^mode:[[:space:]]*//p' <<< "$policy" | head -n 1)
    mode=$(trim "$mode")
    max_age=$(sed -n 's/^max_age:[[:space:]]*//p' <<< "$policy" | head -n 1)
    max_age=$(trim "$max_age")
    local -a patterns=()
    mapfile -t patterns < <(sed -n 's/^mx:[[:space:]]*//p' <<< "$policy")

    case $mode in
        enforce) emit pass "Policy mode: enforce"; points=5 ;;
        testing) emit warn "Policy mode: testing - TLS failures are reported but not enforced"
                 fix MTA-STS "Switch the policy to mode: enforce once TLS-RPT reports are clean, then bump id= in $name"
                 points=3 ;;
        none)    emit warn "Policy mode: none - MTA-STS is disabled"
                 points=1 ;;
        *)       emit fail "Invalid policy mode '$mode'"
                 points=1 ;;
    esac
    if [[ $max_age =~ ^[0-9]+$ ]] && (( max_age < 86400 )); then
        emit warn "max_age=$max_age is short - RFC 8461 recommends several weeks"
    fi
    for h in "${mx_hosts[@]}"; do
        covered=false
        for p in "${patterns[@]}"; do
            mta_sts_mx_match "$h" "$(trim "$p")" && { covered=true; break; }
        done
        if ! $covered; then
            emit warn "MX $h is not covered by the policy's mx: lines - delivery to it fails in enforce mode"
            fix MTA-STS "Add 'mx: $h' to $url and bump id= in $name"
            points=$((points - 2))
        fi
    done
    finish "$points"
}

check_tls_rpt() {
    section TLS-RPT
    local name="_smtp._tls.$domain" records rc rec count
    if $null_mx; then
        emit info "Domain does not receive mail (null MX) - TLS-RPT not needed"
        finish 0 n/a
        return
    fi
    records=$(txt_records "$name")
    rc=$?
    (( rc == 2 )) && { dns_error "$name TXT"; return; }
    rec=$(grep -E '^v=TLSRPTv1[[:space:]]*(;|$)' <<< "$records")
    count=$(grep -c . <<< "$rec")

    if (( count == 0 )); then
        emit fail "LOW: No TLS-RPT record - you won't hear about TLS delivery failures"
        fix TLS-RPT "Receive daily reports about TLS delivery problems" TXT "$name" "v=TLSRPTv1; rua=mailto:tls-reports@$domain"
        finish 0
        return
    fi
    if (( count > 1 )); then
        emit fail "$count TLS-RPT records - reporting is ignored"
        finish 0
        return
    fi
    record "$rec"
    local -A tags=()
    parse_tags tags "$rec"
    if [[ ${tags[rua]:-} =~ (mailto|https): ]]; then
        emit pass "Reports sent to ${tags[rua]}"
        finish 3
    else
        emit warn "Record has no valid rua= destination"
        fix TLS-RPT "Add a report destination" TXT "$name" "v=TLSRPTv1; rua=mailto:tls-reports@$domain"
        finish 1
    fi
}

check_bimi() {
    section BIMI
    local name="default._bimi.$domain" records rc rec logo points=2
    local enforced=false
    [[ $dmarc_policy == quarantine || $dmarc_policy == reject ]] && enforced=true

    if $null_mx; then
        emit info "Domain does not receive mail (null MX) - BIMI not applicable"
        finish 0 n/a
        return
    fi
    records=$(txt_records "$name")
    rc=$?
    (( rc == 2 )) && { dns_error "$name TXT"; return; }
    rec=$(grep -E '^v=BIMI1[[:space:]]*(;|$)' <<< "$records" | head -n 1)

    if [[ -z $rec ]]; then
        emit warn "LOW: No BIMI record (optional - shows your logo in supporting inboxes)"
        $enforced && fix BIMI "Optional: publish your logo as an SVG Tiny PS file" TXT "$name" "v=BIMI1; l=https://$domain/bimi-logo.svg; a="
        finish 0
        return
    fi
    record "$rec"
    local -A tags=()
    parse_tags tags "$rec"
    if [[ -z ${tags[l]:-} ]]; then
        emit info "BIMI explicitly declined (empty l=)"
        finish 0
        return
    fi
    if [[ ${tags[l]} != https://* ]]; then
        emit warn "Logo URL must use HTTPS: ${tags[l]}"
        points=1
    else
        logo=$(curl -fsS --max-time 10 --proto '=https' -r 0-4095 "${tags[l]}" 2>/dev/null | head -c 4096 | tr -d '\0')
        if grep -qi '<svg' <<< "$logo"; then
            emit pass "Logo is an SVG: ${tags[l]}"
        else
            emit warn "Logo at ${tags[l]} could not be fetched or is not an SVG"
            points=1
        fi
    fi
    if [[ -n ${tags[a]:-} ]]; then
        emit pass "Mark certificate (VMC/CMC): ${tags[a]}"
    else
        emit info "No mark certificate (a=) - Gmail and Apple Mail require a VMC or CMC to show the logo"
    fi
    if ! $enforced; then
        emit warn "BIMI requires DMARC p=quarantine or p=reject"
        points=1
    fi
    finish "$points"
}

# Prints the CAA identifier of the CA that issued the HTTPS certificate for the domain.
detect_ca() {
    local issuer
    issuer=$(with_timeout 10 openssl s_client -connect "$domain:443" -servername "$domain" < /dev/null 2>/dev/null |
        openssl x509 -noout -issuer 2>/dev/null)
    case ${issuer,,} in
        *"let's encrypt"*) echo letsencrypt.org ;;
        *digicert*|*geotrust*|*rapidssl*|*thawte*) echo digicert.com ;;
        *sectigo*|*comodo*|*zerossl*) echo sectigo.com ;;
        *"google trust services"*) echo pki.goog ;;
        *amazon*) echo amazon.com ;;
        *globalsign*) echo globalsign.com ;;
        *godaddy*|*starfield*) echo godaddy.com ;;
        *entrust*) echo entrust.net ;;
        *buypass*) echo buypass.com ;;
        *ssl.com*) echo ssl.com ;;
    esac
}

check_caa() {
    section CAA
    local name=$domain out rc line issuers=() ca
    # CAA applies from the closest ancestor that has records (RFC 8659 §3)
    while :; do
        out=$(dns CAA "$name")
        rc=$?
        (( rc == 2 )) && { dns_error "$name CAA"; return; }
        [[ -n $out || $name != *.*.* ]] && break
        name=${name#*.}
    done

    if [[ -z $out ]]; then
        emit warn "LOW: No CAA records - any certificate authority may issue certificates for $domain (including mta-sts.$domain)"
        ca=""
        $skip_tls || ca=$(detect_ca)
        if [[ -n $ca ]]; then
            fix CAA "Allow only the CA that currently issues your HTTPS certificate (add a line for every other CA or CDN you use)" \
                CAA "$domain" "0 issue \"$ca\""
        else
            fix CAA "Allow only the CA(s) that issue your certificates" CAA "$domain" "0 issue \"<your-ca-domain>\""
        fi
        fix CAA "Get notified about rejected certificate requests" CAA "$domain" "0 iodef \"mailto:security@$domain\""
        finish 0
        return
    fi

    while IFS= read -r line; do
        record "$line"
        [[ $line =~ issue(wild)?[[:space:]]+\"([^\"]*)\" ]] && issuers+=("${BASH_REMATCH[2]:-none}")
    done <<< "$out"
    [[ $name != "$domain" ]] && emit info "Inherited from $name"
    (( ${#issuers[@]} )) && emit pass "Allowed CAs: ${issuers[*]}"
    grep -q 'iodef' <<< "$out" || emit info "No iodef record - you won't be told about rejected certificate requests"
    finish 5
}

# --- Fixes and summary --- #

# Splits a queued fix into f_check, f_advice, f_type, f_host and f_value (advice may span lines).
split_fix() {
    local rest=$1
    f_check=${rest%%"$US"*}; rest=${rest#*"$US"}
    f_advice=${rest%%"$US"*}; rest=${rest#*"$US"}
    f_type=${rest%%"$US"*}; rest=${rest#*"$US"}
    f_host=${rest%%"$US"*}
    f_value=${rest#*"$US"}
}

suggest_fixes() {
    local entry check advice type host value
    say ""
    say "${BOLD}${YELLOW}=== Recommended DNS Fixes ===${NC}"
    report ""
    report "=== Recommended DNS Fixes ==="
    if (( ${#fixes[@]} == 0 )); then
        say "${GREEN}No changes needed.${NC}"
        report "No changes needed."
        return
    fi
    for entry in "${fixes[@]}"; do
        split_fix "$entry"
        check=$f_check advice=$f_advice type=$f_type host=$f_host value=$f_value
        advice=${advice//$'\n'/$'\n'      }
        say "${CYAN}[$check]${NC} $advice"
        report "[$check] $advice"
        if [[ -n $value ]]; then
            say "      Type: $type  |  Host: $host  |  Value: $value"
            report "      Type: $type  |  Host: $host  |  Value: $value"
        fi
    done
}

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    s=${s//[[:cntrl:]]/}
    printf '"%s"' "$s"
}

print_json() {
    local score=$1 grade=$2 points=$3 max=$4 elapsed=$5
    local out check sep sep2 line level msg entry fcheck advice type host value
    out="{\"domain\":$(json_escape "$domain"),\"score\":$score,\"grade\":$(json_escape "$grade")"
    out+=",\"points\":$points,\"max_points\":$max,\"elapsed_seconds\":$elapsed,\"checks\":{"
    sep=""
    for check in "${CHECK_ORDER[@]}"; do
        out+="$sep$(json_escape "$check"):{\"status\":$(json_escape "${c_status[$check]:-error}")"
        out+=",\"points\":${c_points[$check]:-0},\"max_points\":${weights[$check]},\"records\":["
        sep2=""
        while IFS= read -r line; do
            [[ -z $line ]] && continue
            out+="$sep2$(json_escape "$line")"
            sep2=","
        done <<< "${c_records[$check]:-}"
        out+="],\"findings\":["
        sep2=""
        while IFS=$US read -r level msg; do
            [[ -z $level ]] && continue
            out+="$sep2{\"level\":$(json_escape "$level"),\"message\":$(json_escape "$msg")}"
            sep2=","
        done <<< "${c_findings[$check]:-}"
        out+="]}"
        sep=","
    done
    out+="},\"fixes\":["
    sep=""
    for entry in "${fixes[@]}"; do
        split_fix "$entry"
        fcheck=$f_check advice=$f_advice type=$f_type host=$f_host value=$f_value
        out+="$sep{\"check\":$(json_escape "$fcheck"),\"advice\":$(json_escape "$advice")"
        out+=",\"type\":$(json_escape "$type"),\"host\":$(json_escape "$host"),\"value\":$(json_escape "$value")}"
        sep=","
    done
    printf '%s]}\n' "$out"
}

# Score Calculation
generate_summary() {
    local elapsed=$(( $(date +%s) - start_time ))
    local check points=0 max=0 score=0 grade grade_name status color
    for check in "${CHECK_ORDER[@]}"; do
        status=${c_status[$check]:-error}
        [[ $status == error || $status == n/a ]] && continue
        points=$((points + ${c_points[$check]}))
        max=$((max + ${weights[$check]}))
    done
    (( max > 0 )) && score=$((points * 100 / max))

    if (( max == 0 )); then grade="⚪ Unknown"; grade_name="Unknown"
    elif (( score >= 90 )); then grade="🟢 Excellent"; grade_name="Excellent"
    elif (( score >= 75 )); then grade="🟡 Good"; grade_name="Good"
    elif (( score >= 50 )); then grade="🟠 Fair"; grade_name="Fair"
    else grade="🔴 Poor"; grade_name="Poor"; fi
    last_score=$score

    report ""
    report "=== Final Report ==="
    for check in "${CHECK_ORDER[@]}"; do
        report "$(printf '%-8s %5s  %s' "$check" "${c_points[$check]:-0}/${weights[$check]}" "${c_status[$check]:-error}")"
    done
    report "Security Score: $score% ($grade_name, $points/$max points)"
    report "Elapsed Time: ${elapsed}s"

    if $json_mode; then
        print_json "$score" "$grade_name" "$points" "$max" "$elapsed"
        return
    fi
    if $quiet; then
        printf '%s: %s%% (%s)\n' "$domain" "$score" "$grade_name"
        return
    fi

    say ""
    say "${BOLD}${CYAN}=== Results for $domain ===${NC}"
    for check in "${CHECK_ORDER[@]}"; do
        status=${c_status[$check]:-error}
        case $status in
            pass) color=$GREEN ;;
            partial|unknown) color=$YELLOW ;;
            fail) color=$RED ;;
            *) color=$CYAN ;;
        esac
        say "$(printf '  %-8s %5s  %s%s%s' "$check" "${c_points[$check]:-0}/${weights[$check]}" "$color" "$status" "$NC")"
    done
    say "Score: ${YELLOW}$score%${NC} ($grade)"
    [[ -n $report_file ]] && say "Report: ${CYAN}$report_file${NC}"
    say "${YELLOW}=== Done in ${elapsed}s ===${NC}"
}

reset_state() {
    c_status=() c_points=() c_records=() c_findings=()
    fixes=() mx_hosts=()
    null_mx=false
    provider="" provider_spf="" provider_dkim=""
    spf_record="" dmarc_policy=""
    rbl_refused_noted=false
}

# Returns 1 if the domain scored below --fail-under.
run_domain() {
    domain=$1
    reset_state
    init_report
    start_time=$(date +%s)
    say "${BOLD}${YELLOW}=== Email Security Checker v$VERSION: $domain ===${NC}"

    check_mx
    check_spf
    check_dkim
    check_dmarc
    check_dnssec
    check_mta_sts
    check_tls_rpt
    check_bimi
    check_caa
    suggest_fixes
    generate_summary

    [[ -z $fail_under ]] || (( last_score >= fail_under ))
}

# Main Flow
main() {
    parse_args "$@"
    setup_colors
    check_deps

    dig_opts=(+time=2 +tries=2)
    [[ -n $resolver ]] && dig_opts=("@$resolver" "${dig_opts[@]}")

    if (( ${#domains[@]} == 0 )); then
        if [[ ! -t 0 ]] || $json_mode; then
            die_usage "No domain given"
        fi
        local input
        read -rp "Enter domain (e.g., example.com): " input
        domains=("$input")
    fi

    local d name status=0
    for d in "${domains[@]}"; do
        name=$(normalize_domain "$d")
        if ! valid_domain "$name"; then
            echo "${RED}Invalid domain: '$d' (expected e.g. example.com)${NC}" >&2
            status=2
            continue
        fi
        if ! run_domain "$name" && (( status == 0 )); then
            status=1
        fi
    done
    exit "$status"
}

main "$@"
