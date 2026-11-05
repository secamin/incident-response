#!/usr/bin/env bash
# =====================================================================================================
#  linux-log-gap-analysis.sh - Linux logging gap analysis for incident response (read-only, no dependencies)
#
#  Runs locally on a (potentially compromised) Linux server and answers:
#    1. Which time frame does every log cover, and how fast is it rotated away?
#    2. Which detection use cases (MITRE ATT&CK) can the current auditd / logging configuration support?
#    3. Was logging weakened or tampered with (auditd stopped, rules removed, logs truncated / deleted ...)?
#    4. Which log files actually reach the SIEM (Splunk Universal Forwarder inputs.conf / syslog forwarding)?
#    5. Who has root / sudo rights, and which accounts logged on (when, from where)?
#  Uses only bash (4.0+), coreutils, grep, sed and awk (gawk or mawk). Nothing on the system is changed.
#  Author : secamin (SIEM Detection Content) - https://github.com/secamin
#  Co-author and contributor: HXM14 - https://github.com/HXM14
#  Tool ID: secamin/log-gap-analysis (Linux)
#  Supported: RHEL / CentOS / Rocky / Alma / Oracle 6-9, Fedora, Ubuntu 14.04+, Debian 8+, SLES 12+, Amazon Linux.
# =====================================================================================================
VERSION='1.0.0'
AUTHOR='secamin'; REPO='https://github.com/secamin'; COAUTHOR='HXM14'; COAUTHOR_REPO='https://github.com/HXM14'; TOOL_ID='secamin/log-gap-analysis'

usage() {
    cat <<'EOF'
Usage: sudo bash linux-log-gap-analysis.sh [options]
linux-log-gap-analysis.sh - by secamin (https://github.com/secamin), co-author and contributor HXM14 (https://github.com/HXM14)

  -o DIR      folder that receives the result folder (default: current directory).
              On a compromised host prefer a USB drive or a mounted share.
  -s START    suspected start of the incident: "YYYY-MM-DD" or "YYYY-MM-DD HH:MM" (local time).
              Every log is checked for whether it still reaches back to this time.
  -d          deep scan: reads auth / syslog / audit logs completely - time gaps, events per hour,
              audit serial gaps (deleted records), wtmp integrity and anti-logging commands. Takes minutes.
  -g MIN      deep scan: report silences longer than MIN minutes (default 60)
  -m LINES    deep scan: maximum lines read per log (default 5000000)
  -p FILE     anti-logging pattern file (default: anti-logging-patterns-linux.txt next to the script)
  -h          this help

Example:
  sudo bash linux-log-gap-analysis.sh -o /mnt/usb/IR -s 2026-10-15 -d
EOF
}

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "This script needs bash 4.0 or later." >&2; exit 2
fi

OUTPUT_PATH=''; SUSPECT_IN=''; DEEP=0; GAP_MIN=60; DEEP_MAX=5000000; PATTERN_FILE=''
while getopts ':o:s:dg:m:p:h' opt; do
    case "$opt" in
        o) OUTPUT_PATH="$OPTARG" ;;
        s) SUSPECT_IN="$OPTARG" ;;
        d) DEEP=1 ;;
        g) GAP_MIN="$OPTARG" ;;
        m) DEEP_MAX="$OPTARG" ;;
        p) PATTERN_FILE="$OPTARG" ;;
        h) usage; exit 0 ;;
        :) echo "Option -$OPTARG needs a value" >&2; usage; exit 2 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage; exit 2 ;;
    esac
done
case "$GAP_MIN" in ''|*[!0-9]*) echo "-g must be a number" >&2; exit 2 ;; esac
case "$DEEP_MAX" in ''|*[!0-9]*) echo "-m must be a number" >&2; exit 2 ;; esac

export LC_ALL=C
umask 077
SCRIPT_PATH="$(cd "$(dirname "$0")" 2>/dev/null && pwd)/$(basename "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
[ -z "$PATTERN_FILE" ] && PATTERN_FILE="$SCRIPT_DIR/anti-logging-patterns-linux.txt"

NOW=$(date +%s)
RUN_START_TXT=$(date '+%Y-%m-%d %H:%M:%S %Z')
TZRAW=$(date +%z)                                   # e.g. +0300
TZOFF=$(( (10#${TZRAW:1:2} * 3600 + 10#${TZRAW:3:2} * 60) ))
[ "${TZRAW:0:1}" = '-' ] && TZOFF=$(( -TZOFF ))
NOWY=$(date +%Y)

SUSPECT=''
if [ -n "$SUSPECT_IN" ]; then
    if printf '%s' "$SUSPECT_IN" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}([ T][0-9]{2}:[0-9]{2}(:[0-9]{2})?)?$'; then
        SUSPECT=$(date -d "$(printf '%s' "$SUSPECT_IN" | tr 'T' ' ')" +%s 2>/dev/null)
    fi
    if [ -z "$SUSPECT" ]; then echo "Cannot parse -s '$SUSPECT_IN' (use YYYY-MM-DD or 'YYYY-MM-DD HH:MM')" >&2; exit 2; fi
fi

HOST=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)
HOST_SHORT=${HOST%%.*}
[ -z "$OUTPUT_PATH" ] && OUTPUT_PATH="$(pwd)" && OUTPUT_GIVEN=0 || OUTPUT_GIVEN=1
mkdir -p "$OUTPUT_PATH" || { echo "Cannot create $OUTPUT_PATH" >&2; exit 2; }
OUTPUT_PATH="$(cd "$OUTPUT_PATH" && pwd)"
OUT="$OUTPUT_PATH/LinuxLogGap_${HOST_SHORT}_$(date +%Y%m%d_%H%M%S)"
RAW="$OUT/raw"; W="$OUT/.work"
mkdir -p "$RAW" "$W" || exit 2

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
SYSTEMD=0; [ -d /run/systemd/system ] && SYSTEMD=1

# ---- result tables (TSV) ----------------------------------------------------------------------------
F_FIND="$W/findings.tsv"; F_LOGS="$W/logs.tsv"; F_EV="$W/events.tsv"; F_WF="$W/workflow.tsv"; F_AR="$W/auditrules.tsv"
F_UC="$W/usecases.tsv"; F_SP="$W/splunk.tsv"; F_SPF="$W/splunk_files.tsv"; F_CFG="$W/config.tsv"; F_AGENT="$W/agents.tsv"
F_USERS="$W/users.tsv"; F_PRIV="$W/privileged.tsv"; F_LOGON="$W/logons.tsv"; F_FAIL="$W/failed.tsv"; F_CHG="$W/changes.tsv"
F_KEYS="$W/sshkeys.tsv"; F_SESS="$W/sessions.tsv"; F_SUDO="$W/sudo_usage.tsv"; F_AREA="$W/score_areas.tsv"
F_DEEP="$W/deep.tsv"; F_GAPS="$W/deep_gaps.tsv"; F_HIST="$W/deep_hist.tsv"; F_CMD="$W/deep_cmds.tsv"; F_BOOT="$W/boots.tsv"
for f in "$F_FIND" "$F_LOGS" "$F_EV" "$F_WF" "$F_AR" "$F_UC" "$F_SP" "$F_SPF" "$F_CFG" "$F_AGENT" "$F_USERS" "$F_PRIV" "$F_LOGON" \
         "$F_FAIL" "$F_CHG" "$F_KEYS" "$F_SESS" "$F_SUDO" "$F_AREA" "$F_DEEP" "$F_GAPS" "$F_HIST" "$F_CMD" "$F_BOOT"; do : > "$f"; done
COLLOG="$OUT/collection.log"; : > "$COLLOG"

# =====================================================================================================
#  Helpers
# =====================================================================================================
c_reset=''; c_cyan=''; c_green=''; c_yellow=''; c_red=''
if [ -t 2 ]; then c_reset=$'\e[0m'; c_cyan=$'\e[36m'; c_green=$'\e[32m'; c_yellow=$'\e[33m'; c_red=$'\e[31m'; fi
step() {   # step LEVEL MESSAGE
    local lvl="$1"; shift
    local line; line=$(printf '%s %-5s %s' "$(date +%H:%M:%S)" "$lvl" "$*")
    printf '%s\n' "$line" >> "$COLLOG"
    local c=''
    case "$lvl" in STEP) c=$c_cyan ;; OK) c=$c_green ;; WARN) c=$c_yellow ;; ERROR) c=$c_red ;; esac
    printf '%s%s%s\n' "$c" "$line" "$c_reset" >&2
}
clean() { printf '%s' "$*" | tr '\t\r\n' '   '; }
add_finding() {   # severity category title detail evidence recommendation mitre
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(clean "$1")" "$(clean "$2")" "$(clean "$3")" "$(clean "${4:-}")" "$(clean "${5:-}")" "$(clean "${6:-}")" "$(clean "${7:-}")" >> "$F_FIND"
}
add_event() {     # epoch severity source kind title detail
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${1:-0}" "$2" "$(clean "$3")" "$4" "$(clean "$5")" "$(clean "${6:-}")" >> "$F_EV"
}
add_wf() { printf '%s\t%s\t%s\n' "$(clean "$1")" "$2" "$(clean "${3:-}")" >> "$F_WF"; }
add_cfg() { printf '%s\t%s\t%s\n' "$(clean "$1")" "$(clean "$2")" "$(clean "${3:-}")" >> "$F_CFG"; }   # setting value state(ok|warn|bad|na)
have() { command -v "$1" >/dev/null 2>&1; }
run_to() {        # run_to SECONDS cmd args...  (timeout when available)
    local s="$1"; shift
    if have timeout; then timeout "$s" "$@"; else "$@"; fi
}
catf() {          # decompress transparently
    case "$1" in
        *.gz)  gzip -dc -- "$1" 2>/dev/null ;;
        *.xz)  xz -dc -- "$1" 2>/dev/null ;;
        *.bz2) bzip2 -dc -- "$1" 2>/dev/null ;;
        *.zst) zstd -dcq -- "$1" 2>/dev/null ;;
        *)     cat -- "$1" 2>/dev/null ;;
    esac
}
fsize() { stat -c %s -- "$1" 2>/dev/null || echo 0; }
fmtime() { stat -c %Y -- "$1" 2>/dev/null || echo 0; }
fmt_epoch() { [ -n "${1:-}" ] && [ "${1:-0}" -gt 0 ] 2>/dev/null && date -d "@$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null; }
proc_running() {  # proc_running NAME  (exact process name)
    if have pgrep; then pgrep -x "$1" >/dev/null 2>&1; return $?; fi
    local p; for p in /proc/[0-9]*/comm; do [ "$(cat "$p" 2>/dev/null)" = "$1" ] && return 0; done; return 1
}
svc_state() {     # svc_state UNIT  -> active|inactive|failed|unknown ; enabled state in SVC_ENABLED
    SVC_ENABLED='unknown'
    if [ $SYSTEMD -eq 1 ] && have systemctl; then
        SVC_ENABLED=$(systemctl is-enabled "$1" 2>/dev/null | head -1); [ -z "$SVC_ENABLED" ] && SVC_ENABLED='not-found'
        local a; a=$(systemctl is-active "$1" 2>/dev/null | head -1); echo "${a:-unknown}"
    elif have chkconfig; then
        chkconfig --list "$1" 2>/dev/null | grep -q ':on' && SVC_ENABLED='enabled' || SVC_ENABLED='disabled'
        service "$1" status >/dev/null 2>&1 && echo active || echo inactive
    else
        echo unknown
    fi
}
rotated_set() {   # all files of a log incl. rotations, oldest first (by mtime)
    local f="$1"
    ls -1tr -- "$f" "$f".[0-9]* "$f"-[0-9]* 2>/dev/null
}
AUD_CONF=/etc/audit/auditd.conf
audv() { [ -r "$AUD_CONF" ] || return 0; awk -F= -v k="$1" '{ gsub(/[ \t]/,"",$1) } $1==k { v=$2; gsub(/^[ \t]+|[ \t]+$/,"",v); print v; exit }' "$AUD_CONF"; }
json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' | tr -d '\000-\010\013\014\016-\037' | awk 'BEGIN{ORS=""} NR>1{print "\\n"} {print}'; }

# ---- shared awk library: timestamp parsing / formatting without mktime (works with mawk and gawk) ----
AWKLIB='
function dfc(y,m,d,   era,yoe,doy,doe) { if (m<=2) y--; era=int((y>=0?y:y-399)/400); yoe=y-era*400
    doy=int((153*(m+(m>2?-3:9))+2)/5)+d-1; doe=yoe*365+int(yoe/4)-int(yoe/100)+doy; return era*146097+doe-719468 }
function ep(y,m,d,H,M,S) { return dfc(y,m,d)*86400+H*3600+M*60+S }
function fmt(e,   z,era,doe,yoe,y,doy,mp,d,m,s) { if (e=="" || e+0<=0) return ""; e=int(e)+TZOFF; z=int(e/86400); s=e-z*86400
    if (s<0) { s+=86400; z-- }; z+=719468; era=int((z>=0?z:z-146096)/146097); doe=z-era*146097
    yoe=int((doe-int(doe/1460)+int(doe/36524)-int(doe/146096))/365); y=yoe+era*400; doy=doe-(365*yoe+int(yoe/4)-int(yoe/100))
    mp=int((5*doy+2)/153); d=doy-int((153*mp+2)/5)+1; m=mp+(mp<10?3:-9); if (m<=2) y++
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d",y,m,d,int(s/3600),int((s%3600)/60),s%60) }
function monnum(s) { return index("JanFebMarAprMayJunJulAugSepOctNovDec",s) ? (index("JanFebMarAprMayJunJulAugSepOctNovDec",s)+2)/3 : 0 }
function isots(s,   y,m,d,H,M,S,e,r,sg,oh,om) {
    y=substr(s,1,4)+0; m=substr(s,6,2)+0; d=substr(s,9,2)+0; H=substr(s,12,2)+0; M=substr(s,15,2)+0; S=substr(s,18,2)+0
    e=ep(y,m,d,H,M,S); r=substr(s,20); sub(/^[.,][0-9]+/,"",r)
    if (r ~ /^Z/) return e
    if (r ~ /^[+-][0-9][0-9]:?[0-9][0-9]/) { sg=(substr(r,1,1)=="-")?-1:1; oh=substr(r,2,2)+0; om=(substr(r,4,1)==":")?substr(r,5,2)+0:substr(r,4,2)+0
        return e - sg*(oh*3600+om*60) }
    return e - TZOFF }
function sysl(mo,dd,tt,   m,e) { m=monnum(mo); if (!m) return -1
    e=ep(NOWY,m,dd+0,substr(tt,1,2)+0,substr(tt,4,2)+0,substr(tt,7,2)+0)-TZOFF
    if (e > NOW+86400) e=ep(NOWY-1,m,dd+0,substr(tt,1,2)+0,substr(tt,4,2)+0,substr(tt,7,2)+0)-TZOFF
    return e }
function ts(line,   p,a,n) {
    if (match(line,/audit\([0-9]+\.[0-9]+:/)) { p=substr(line,RSTART+6); return substr(p,1,index(p,".")-1)+0 }
    if (line ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return isots(line)
    if (line ~ /^[A-Z][a-z][a-z] [ 0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return sysl(substr(line,1,3),substr(line,5,2),substr(line,8,8))
    if (line ~ /^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]\.[0-9]/) return int(substr(line,1,10))
    if (line ~ /^[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return ep(substr(line,7,4)+0,substr(line,1,2)+0,substr(line,4,2)+0,substr(line,12,2)+0,substr(line,15,2)+0,substr(line,18,2)+0)-TZOFF
    if (match(line,/\[[0-9][0-9]\/[A-Z][a-z][a-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9] [+-][0-9][0-9][0-9][0-9]\]/)) {
        p=substr(line,RSTART+1,RLENGTH-2)
        return ep(substr(p,8,4)+0,monnum(substr(p,4,3)),substr(p,1,2)+0,substr(p,13,2)+0,substr(p,16,2)+0,substr(p,19,2)+0) - ((substr(p,22,1)=="-")?-1:1)*(substr(p,23,2)*3600+substr(p,25,2)*60) }
    if (line ~ /^[A-Z][a-z][a-z] [A-Z][a-z][a-z] [ 0-9]?[0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] [0-9][0-9][0-9][0-9]/) {
        n=split(line,a," "); return ep(a[5]+0,monnum(a[2]),a[3]+0,substr(a[4],1,2)+0,substr(a[4],4,2)+0,substr(a[4],7,2)+0)-TZOFF }
    return -1 }
function h(s) { gsub(/&/,"\\&amp;",s); gsub(/</,"\\&lt;",s); gsub(/>/,"\\&gt;",s); gsub(/"/,"\\&quot;",s); return s }
function ispub(ip,   a,n) {
    if (ip=="" || ip=="-" || ip ~ /^(::1|127\.|0\.|10\.|192\.168\.|169\.254\.)/ || ip ~ /^(fe80|fc|fd)/) return 0
    if (ip ~ /^::ffff:/) ip=substr(ip,8)
    if (ip ~ /:/) return (ip ~ /^[0-9a-fA-F:]+$/) ? 1 : 0
    if (ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
    n=split(ip,a,"."); if (a[1]==172 && a[2]>=16 && a[2]<=31) return 0; if (a[1]==100 && a[2]>=64 && a[2]<=127) return 0
    if (a[1]==10 || a[1]==127) return 0
    return 1 }
'
awk_split() {   # separate awk options (-F x, -v a=b) from program and files, wherever they appear
    AO=(); AP=''; AF=(); local havep=0
    while [ $# -gt 0 ]; do
        case "$1" in
            -F|-v) AO+=("$1" "$2"); shift 2 ;;
            -F?*|-v?*) AO+=("$1"); shift ;;
            *) if [ $havep -eq 0 ]; then AP="$1"; havep=1; else AF+=("$1"); fi; shift ;;
        esac
    done
}
awkx() { local AO AP AF; awk_split "$@"; awk -v NOW="$NOW" -v TZOFF="$TZOFF" -v NOWY="$NOWY" "${AO[@]}" "$AWKLIB$AP" "${AF[@]}"; }

first_ts() {   # first parseable timestamp of a (possibly compressed) file
    catf "$1" | head -n 200 | awkx '{ t=ts($0); if (t>0) { print t; exit } }'
}
last_ts() {
    case "$1" in
        *.gz|*.xz|*.bz2|*.zst) catf "$1" | tail -n 200 ;;
        *) tail -n 200 -- "$1" 2>/dev/null ;;
    esac | awkx '{ t=ts($0); if (t>0) last=t } END { if (last>0) print last }'
}

# =====================================================================================================
#  1. System profile
# =====================================================================================================
collect_system() {
    step STEP 'System profile and roles'
    OS_NAME=''; OS_ID=''; OS_VER=''
    if [ -r /etc/os-release ]; then
        OS_NAME=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-$NAME}"); OS_ID=$(. /etc/os-release 2>/dev/null; echo "${ID:-}"); OS_VER=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
        cp /etc/os-release "$RAW/os-release.txt" 2>/dev/null
    elif [ -r /etc/redhat-release ]; then OS_NAME=$(cat /etc/redhat-release); OS_ID='rhel'
    elif [ -r /etc/SuSE-release ]; then OS_NAME=$(head -1 /etc/SuSE-release); OS_ID='sles'
    else OS_NAME=$(uname -s); fi
    KERNEL=$(uname -r); ARCH=$(uname -m)
    FQDN=$(hostname -f 2>/dev/null || echo "$HOST")
    UPTIME_S=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
    BOOT=$(( NOW - UPTIME_S ))
    TZNAME=$(date +%Z)
    [ -L /etc/localtime ] && TZNAME="$(readlink /etc/localtime | sed 's#.*zoneinfo/##') ($TZRAW)" || TZNAME="$TZNAME ($TZRAW)"
    RUN_USER=$(id -un 2>/dev/null)
    VIRT=''; have systemd-detect-virt && VIRT=$(systemd-detect-virt 2>/dev/null)
    SELINUX='not present'
    if have getenforce; then SELINUX=$(getenforce 2>/dev/null)
    elif [ -d /sys/kernel/security/apparmor ]; then SELINUX='AppArmor loaded'; fi
    IPS=$( (ip -o -4 addr show 2>/dev/null | awk '$2!="lo"{print $4}' | tr '\n' ' ') || hostname -I 2>/dev/null )
    # roles from running / installed services
    ROLES=''
    addrole() { case " $ROLES " in *" $1 "*) ;; *) ROLES="$ROLES $1" ;; esac; }
    for p in apache2 httpd nginx lighttpd caddy tomcat java php-fpm php-fpm8 php-fpm7; do proc_running "$p" && case "$p" in java|tomcat) ;; *) addrole WEB ;; esac; done
    [ -d /etc/nginx ] || [ -d /etc/httpd ] || [ -d /etc/apache2 ] && addrole WEB
    for p in mysqld mariadbd postgres postmaster mongod oracle ora_pmon redis-server; do proc_running "$p" && addrole DB; done
    for p in dockerd containerd kubelet podman crio; do proc_running "$p" && addrole CONTAINER; done
    proc_running named && addrole DNS; proc_running slapd && addrole LDAP; proc_running ns-slapd && addrole IPA
    for p in master postfix sendmail exim exim4; do proc_running "$p" && addrole MAIL; done
    proc_running sshd || addrole NOSSH
    ROLES=$(echo $ROLES)
    SSH_ON=0; proc_running sshd && SSH_ON=1
    step OK "$OS_NAME | kernel $KERNEL | roles: ${ROLES:-none} | root: $IS_ROOT"
    [ $IS_ROOT -eq 0 ] && step WARN 'Not running as root - auth / audit logs, auditctl and /etc/shadow will not be readable'
    [ $OUTPUT_GIVEN -eq 0 ] && step WARN 'No -o given: results are written to the current directory on this host'
    { uname -a; echo; id; echo; cat /proc/cmdline 2>/dev/null; } > "$RAW/system.txt" 2>/dev/null
    ps -eo pid,ppid,user,lstart,cmd > "$RAW/processes.txt" 2>/dev/null || ps aux > "$RAW/processes.txt" 2>/dev/null
}

# =====================================================================================================
#  2. Log inventory
# =====================================================================================================
LOGROTATE_ALL=''
logrotate_for() {   # print "rotate periodDays maxage size" for a path (best effort)
    [ -z "$LOGROTATE_ALL" ] && LOGROTATE_ALL=$( { [ -r /etc/logrotate.conf ] && cat /etc/logrotate.conf; for f in /etc/logrotate.d/*; do [ -f "$f" ] && { echo; cat "$f"; }; done; } 2>/dev/null )
    printf '%s\n' "$LOGROTATE_ALL" | awk -v P="$1" '
        function per(w) { return w=="daily"?1:(w=="weekly"?7:(w=="monthly"?30:(w=="yearly"?365:(w=="hourly"?1/24:0)))) }
        { sub(/#.*/,"") }
        depth==0 && /\{/ { hdr=$0; sub(/\{.*/,"",hdr); n=split(hdr,a,/[ \t]+/); hit=0
            for (i=1;i<=n;i++) { if (a[i]=="") continue; pat=a[i]; gsub(/"/,"",pat); rx=pat; gsub(/[.+?()|^$]/,"\\\\&",rx); gsub(/\*/,".*",rx)
                if (P ~ ("^" rx "$")) hit=1 }
            depth=1; if (hit) { sr=""; sp=""; sm=""; ss="" }; next }
        depth==1 && /\}/ { depth=0; if (hit) { found=1; fr=sr; fp=sp; fm=sm; fs=ss; hit=0 }; next }
        { w=$1 }
        depth==0 && w=="rotate" { gr=$2 } depth==0 && per(w)>0 { gp=per(w) } depth==0 && w=="maxage" { gm=$2 } depth==0 && (w=="size"||w=="maxsize") { gs=$2 }
        depth==1 && hit && w=="rotate" { sr=$2 } depth==1 && hit && per(w)>0 { sp=per(w) } depth==1 && hit && w=="maxage" { sm=$2 } depth==1 && hit && (w=="size"||w=="maxsize") { ss=$2 }
        END { if (!found) { print "none"; exit }
              if (fr=="") fr=gr; if (fp=="") fp=gp; if (fm=="") fm=gm; if (fs=="") fs=gs
              printf "%s %s %s %s\n", (fr==""?1:fr), (fp==""?0:fp), (fm==""?"-":fm), (fs==""?"-":fs) }'
}

inventory_file() {  # kind name why path
    local kind="$1" name="$2" why="$3" path="$4"
    local status='OK' nfiles=0 bytes=0 oldest='' newest='' lines=0 rate='' span='' mode='' cap='' note=''
    if [ ! -e "$path" ]; then
        printf '%s\t%s\t%s\tMissing\t0\t0\t\t\t0\t\t\t\t\t%s\t\n' "$kind" "$name" "$path" "$why" >> "$F_LOGS"; return
    fi
    if [ ! -r "$path" ]; then
        printf '%s\t%s\t%s\tUnreadable\t0\t%s\t\t\t0\t\t\t\t\t%s\tpermission denied\n' "$kind" "$name" "$path" "$(fsize "$path")" "$why" >> "$F_LOGS"; return
    fi
    local files; mapfile -t files < <(rotated_set "$path")
    nfiles=${#files[@]}
    local f; for f in "${files[@]}"; do bytes=$(( bytes + $(fsize "$f") )); done
    case "$kind" in
        wtmp|btmp)
            if have utmpdump; then
                oldest=$(for f in "${files[@]}"; do catf "$f" > "$W/utmp.tmp"; utmpdump "$W/utmp.tmp" 2>/dev/null | head -n 50; break; done | awkx -F'] \\[' '{ t=$8; gsub(/[\[\]]/,"",t); t=ts(t); if (t>0) { print t; exit } }')
                newest=$(utmpdump "$path" 2>/dev/null | tail -n 50 | awkx -F'] \\[' '{ t=$8; gsub(/[\[\]]/,"",t); t=ts(t); if (t>0) l=t } END { if (l>0) print l }')
                lines=$(utmpdump "$path" 2>/dev/null | wc -l)
            fi
            mode='binary (utmp)' ;;
        lastlog) mode='binary (sparse)'; oldest=''; newest=$(fmtime "$path") ;;
        *)
            oldest=$(first_ts "${files[0]}")
            newest=$(last_ts "$path")
            [ -z "$newest" ] && [ $nfiles -gt 1 ] && newest=$(last_ts "${files[$((nfiles-2))]}")
            lines=$(wc -l < "$path" 2>/dev/null || echo 0)
            local cfirst; cfirst=$(first_ts "$path")
            if [ -n "$cfirst" ] && [ -n "$newest" ] && [ "$newest" -gt "$cfirst" ] 2>/dev/null; then
                rate=$(awk -v l="$lines" -v s="$(( newest - cfirst ))" 'BEGIN{ printf "%.2f", l/(s/3600) }')
                local bph; bph=$(awk -v b="$(fsize "$path")" -v s="$(( newest - cfirst ))" 'BEGIN{ printf "%.0f", b/(s/3600) }')
            fi
            if [ "$kind" = audit ]; then
                mode="auditd: ${AUD_NUMLOGS:-?} x ${AUD_MAXLOG:-?} MB, ${AUD_MAXACT:-?}"
                if [ -n "${bph:-}" ] && [ "${bph:-0}" -gt 0 ] && [ -n "${AUD_NUMLOGS:-}" ] && [ -n "${AUD_MAXLOG:-}" ]; then
                    cap=$(awk -v n="$AUD_NUMLOGS" -v m="$AUD_MAXLOG" -v b="$bph" 'BEGIN{ printf "%.1f", n*m*1048576/b }')
                fi
            else
                local lr; lr=$(logrotate_for "$path")
                if [ "$lr" = none ]; then mode='no logrotate rule'
                else
                    set -- $lr
                    mode="logrotate: rotate $1"; [ "$2" != 0 ] && mode="$mode, every $(awk -v p="$2" 'BEGIN{ if (p<1) print "hour"; else if (p==1) print "day"; else if (p==7) print "week"; else if (p==30) print "month"; else print p " days" }')"
                    [ "$4" != '-' ] && mode="$mode, size $4"; [ "$3" != '-' ] && mode="$mode, maxage $3 d"
                    if [ "$2" != 0 ]; then cap=$(awk -v r="$1" -v p="$2" 'BEGIN{ printf "%.1f", (r+1)*p*24 }')
                        [ "$3" != '-' ] && cap=$(awk -v c="$cap" -v m="$3" 'BEGIN{ x=m*24; printf "%.1f", (x<c?x:c) }'); fi
                fi
            fi ;;
    esac
    [ -n "$oldest" ] && [ -n "$newest" ] && span=$(( newest - oldest ))
    [ "$bytes" -eq 0 ] && status='Empty'
    if [ "$status" = OK ] && [ "$(fsize "$path")" -eq 0 ] && [ $nfiles -gt 1 ]; then
        local age=$(( NOW - $(fmtime "$path") )); [ $age -gt 86400 ] && note='current file empty for more than a day'
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$name" "$path" "$status" "$nfiles" "$bytes" "$oldest" "$newest" "$lines" "$rate" "$span" "$mode" "$cap" "$why" "$note" >> "$F_LOGS"
}

collect_logs() {
    step STEP 'Log inventory'
    # auditd configuration first (needed for capacity)
    AUD_LOG=/var/log/audit/audit.log
    AUD_NUMLOGS=''; AUD_MAXLOG=''; AUD_MAXACT=''
    if [ -r "$AUD_CONF" ]; then
        cp "$AUD_CONF" "$RAW/auditd.conf" 2>/dev/null
        local lf; lf=$(audv log_file); [ -n "$lf" ] && AUD_LOG="$lf"
        AUD_NUMLOGS=$(audv num_logs); AUD_MAXLOG=$(audv max_log_file); AUD_MAXACT=$(audv max_log_file_action)
    fi
    AUTH_LOG=''; SYS_LOG=''
    local defs=(
        "auth|Authentication|Logons, sudo / su, SSH, account changes|/var/log/auth.log /var/log/secure"
        "syslog|System log|Services, kernel, daemons, tampering messages|/var/log/syslog /var/log/messages"
        "audit|Audit (auditd)|Process execution, file watches, syscalls|$AUD_LOG"
        "kern|Kernel|Kernel modules and kernel messages|/var/log/kern.log"
        "cron|Cron|Scheduled job execution|/var/log/cron /var/log/cron.log"
        "sudo|Sudo log file|Sudo commands (if logfile= is set)|/var/log/sudo.log"
        "pkg|Package manager|Package installs and removals|/var/log/dpkg.log /var/log/dnf.rpm.log /var/log/dnf.log /var/log/yum.log /var/log/zypp/history"
        "wtmp|Login records (wtmp)|Successful logons, reboots|/var/log/wtmp"
        "btmp|Failed logins (btmp)|Failed logons|/var/log/btmp"
        "lastlog|Last login (lastlog)|Last logon per account|/var/log/lastlog"
        "web|Web access log|Web requests - web shells, exploitation|/var/log/apache2/access.log /var/log/httpd/access_log /var/log/nginx/access.log"
    )
    local d kind name why cands c chosen
    for d in "${defs[@]}"; do
        IFS='|' read -r kind name why cands <<< "$d"
        chosen=''
        for c in $cands; do [ -e "$c" ] && { chosen="$c"; break; }; done
        if [ -z "$chosen" ]; then
            case "$kind" in web) case " $ROLES " in *" WEB "*) ;; *) continue ;; esac ;; sudo|kern|pkg) continue ;; esac
            chosen=${cands%% *}
        fi
        inventory_file "$kind" "$name" "$why" "$chosen"
        [ "$kind" = auth ] && AUTH_LOG="$chosen"; [ "$kind" = syslog ] && SYS_LOG="$chosen"
    done
    # extra destinations for auth facility from (r)syslog configuration
    local extra
    extra=$(cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | grep -E '^[^#$]*\bauth(priv)?\.' | awk '{ print $NF }' | sed 's/^-//' | grep '^/' | sort -u)
    for c in $extra; do
        [ "$c" = "$AUTH_LOG" ] || [ "$c" = "$SYS_LOG" ] && continue
        grep -q "	$c	" "$F_LOGS" && continue
        inventory_file auth2 "Auth facility ($(basename "$c"))" 'Authentication messages (rsyslog destination)' "$c"
    done
    # journald
    JOURNAL_PERSIST=0; JOURNAL_STORAGE='n/a'
    if [ $SYSTEMD -eq 1 ] && have journalctl; then
        local jconf; jconf=$( { cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf /usr/lib/systemd/journald.conf.d/*.conf 2>/dev/null; } )
        printf '%s\n' "$jconf" > "$RAW/journald.conf.txt"
        jv() { printf '%s\n' "$jconf" | grep -E "^[[:space:]]*$1=" | tail -1 | cut -d= -f2- | tr -d ' '; }
        JOURNAL_STORAGE=$(jv Storage); [ -z "$JOURNAL_STORAGE" ] && JOURNAL_STORAGE='auto'
        J_MAXUSE=$(jv SystemMaxUse); J_RET=$(jv MaxRetentionSec); J_FWD=$(jv ForwardToSyslog)
        if [ "$JOURNAL_STORAGE" = persistent ] || { [ "$JOURNAL_STORAGE" = auto ] && [ -d /var/log/journal ]; }; then JOURNAL_PERSIST=1; fi
        local jo jn ju jb
        jo=$(run_to 60 journalctl -q --no-pager -o short-unix 2>/dev/null | head -n 1 | awkx '{ t=ts($0); if (t>0) print t }')
        jn=$(run_to 30 journalctl -q --no-pager -o short-unix -r -n 1 2>/dev/null | awkx '{ t=ts($0); if (t>0) print t }')
        ju=$(run_to 30 journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMGT]' | head -1)
        jb=$(awk -v u="$ju" 'BEGIN{ n=u+0; s=substr(u,length(u)); m=(s=="K")?1024:((s=="M")?1048576:((s=="G")?1073741824:((s=="T")?1099511627776:1))); printf "%.0f", n*m }')
        local jspan=''; [ -n "$jo" ] && [ -n "$jn" ] && jspan=$(( jn - jo ))
        local jmode="Storage=$JOURNAL_STORAGE"; [ $JOURNAL_PERSIST -eq 0 ] && jmode="$jmode (volatile - lost at reboot)"
        [ -n "$J_MAXUSE" ] && jmode="$jmode, SystemMaxUse=$J_MAXUSE"; [ -n "$J_RET" ] && jmode="$jmode, MaxRetentionSec=$J_RET"
        local jst=OK; [ -z "$jo" ] && jst='Empty'
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' journal 'systemd journal' "$( [ $JOURNAL_PERSIST -eq 1 ] && echo /var/log/journal || echo /run/log/journal )" "$jst" '' "${jb:-0}" "$jo" "$jn" '' '' "$jspan" "$jmode" '' 'All services, kernel, auth (journald)' '' >> "$F_LOGS"
        run_to 30 journalctl --list-boots --no-pager 2>/dev/null > "$RAW/journal_boots.txt"
    fi
    # boot / shutdown times from wtmp (used to explain service stops and gaps)
    if have utmpdump && [ -r /var/log/wtmp ]; then
        for f in $(rotated_set /var/log/wtmp); do catf "$f" > "$W/utmp.tmp"; utmpdump "$W/utmp.tmp" 2>/dev/null; done |
            awkx -F'] \\[' '{ ty=$1; gsub(/[\[\] ]/,"",ty); u=$4; gsub(/ +$/,"",u); t=$8; gsub(/[\[\]]/,"",t); t=ts(t)
                if (t<=0) next; if (ty==2) print t "\tboot"; else if (ty==1 && u ~ /shutdown/) print t "\tshutdown"; else if (ty==1 && u ~ /runlevel/) print t "\trunlevel" }' >> "$F_BOOT"
    fi
    echo "$BOOT	boot" >> "$F_BOOT"
    local n; n=$(grep -c . "$F_LOGS")
    step OK "$n log sources inventoried (auth: ${AUTH_LOG:-none}, syslog: ${SYS_LOG:-none}, journal: $JOURNAL_STORAGE)"
}

# =====================================================================================================
#  3. auditd state and rule baseline
# =====================================================================================================
# ID|Name|MITRE|regex on rule text|why|key(1)
AUDIT_BASELINE=(
'A01|Process execution (execve)|T1059.004|-S ([a-z0-9_]+,)*execve|Every executed command with arguments - the core of Linux IR|1'
'A02|Identity files (passwd / shadow / group)|T1136.001, T1098|/etc/(shadow|passwd)|Account creation and password changes|1'
'A03|Sudoers changes|T1548.003|/etc/sudoers|Privilege escalation persistence|1'
'A04|SSH server configuration|T1098.004|/etc/ssh/sshd_config|Backdoored SSH configuration|1'
'A05|Cron jobs|T1053.003|/etc/cron|/var/spool/cron|/etc/crontab|Scheduled task persistence|1'
'A06|Systemd units|T1543.002|/etc/systemd/|/usr/lib/systemd/|/lib/systemd/|Service persistence|1'
'A07|Kernel module loading|T1547.006, T1014|init_module|finit_module|delete_module|/s?bin/(insmod|modprobe|rmmod|kmod)|Rootkits and malicious drivers|1'
'A08|System time changes|T1070.006|adjtimex|settimeofday|clock_settime|/etc/localtime|Timestamp manipulation|0'
'A09|Audit configuration and tools|T1562.012|/etc/audit|/var/log/audit|/s?bin/(auditctl|auditd|augenrules)|Disabling or modifying the audit system|1'
'A10|Login records (wtmp / btmp / lastlog)|T1070.003|/var/log/(wtmp|btmp|lastlog|faillog)|/(var/)?run/utmp|Log cleaners editing login records|1'
'A11|Library preload (ld.so.preload)|T1574.006|/etc/ld\.so\.preload|Userland rootkits (LD_PRELOAD)|1'
'A12|Privileged commands (sudo / su / passwd)|T1548|/usr/bin/(sudo|su|passwd|newgrp|chsh)|/bin/su|Use of privilege-changing binaries|0'
'A13|Permission / ownership changes|T1222.002, T1548.001|chmod|fchmod|chown|setxattr|Setuid backdoors, permission tampering|0'
'A14|Process injection (ptrace)|T1055.008|ptrace|Memory injection, credential theft from processes|0'
'A15|Root SSH authorized_keys|T1098.004|/root/\.ssh|SSH key persistence for root|1'
'A16|PAM configuration|T1556.003|/etc/pam\.d|/etc/security|PAM backdoors capturing passwords|1'
'A17|Mounts|T1611, T1052|-S ([a-z0-9_]+,)*mount|Mounting file systems / removable media|0'
'A18|Unsuccessful file access|T1083|EACCES|EPERM|Denied access to sensitive files (CIS)|0'
'A19|File deletion / rename by users|T1070.004|unlink|rename|Evidence deletion (CIS)|0'
'A20|Network connections (connect)|T1071|-S ([a-z0-9_]+,)*connect|Outbound connections / C2 (high volume - optional)|0'
'A21|Hosts / network configuration|T1565.001|/etc/hosts|sethostname|setdomainname|/etc/resolv\.conf|DNS / name resolution tampering|0'
)

collect_audit() {
    step STEP 'auditd state and audit rules'
    AUD_INSTALLED=0; AUD_RUNNING=0; AUD_ENABLED=''; AUD_LOST=''; AUD_BACKLOG=''; AUD_RULES_LOADED=0; AUD_RULES_PERSIST=0; AUD_IMMUTABLE=0
    AUD_LOADED_TXT=''; AUD_PERSIST_TXT=''; AUD_READ=0
    grep -qw 'audit=0' /proc/cmdline 2>/dev/null && KERNEL_AUDIT_OFF=1 || KERNEL_AUDIT_OFF=0
    { have auditctl || have auditd || [ -d /etc/audit ]; } && AUD_INSTALLED=1
    proc_running auditd && AUD_RUNNING=1
    AUD_SVC=$(svc_state auditd); AUD_SVC_EN=$SVC_ENABLED
    if [ $AUD_INSTALLED -eq 1 ] && have auditctl && [ $IS_ROOT -eq 1 ]; then
        local st; st=$(auditctl -s 2>&1); printf '%s\n' "$st" > "$RAW/auditctl_status.txt"
        AUD_ENABLED=$(printf '%s\n' "$st" | awk '$1=="enabled"{print $2} /enabled=/{ for(i=1;i<=NF;i++) if ($i ~ /^enabled=/) { split($i,a,"="); print a[2] } }' | head -1)
        AUD_LOST=$(printf '%s\n' "$st" | awk '$1=="lost"{print $2} /lost=/{ for(i=1;i<=NF;i++) if ($i ~ /^lost=/) { split($i,a,"="); print a[2] } }' | head -1)
        AUD_BACKLOG=$(printf '%s\n' "$st" | awk '$1=="backlog_limit"{print $2} /backlog_limit=/{ for(i=1;i<=NF;i++) if ($i ~ /^backlog_limit=/) { split($i,a,"="); print a[2] } }' | head -1)
        AUD_LOADED_TXT=$(auditctl -l 2>&1); printf '%s\n' "$AUD_LOADED_TXT" > "$RAW/auditctl_rules.txt"
        printf '%s\n' "$AUD_LOADED_TXT" | grep -qi 'no rules' && AUD_LOADED_TXT=''
        AUD_RULES_LOADED=$(printf '%s\n' "$AUD_LOADED_TXT" | grep -c '^-')
        AUD_READ=1
        [ "$AUD_ENABLED" = 2 ] && AUD_IMMUTABLE=1
    fi
    AUD_PERSIST_TXT=$(cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -E '^[[:space:]]*-' )
    printf '%s\n' "$AUD_PERSIST_TXT" > "$RAW/audit_rules_persistent.txt"
    AUD_RULES_PERSIST=$(printf '%s\n' "$AUD_PERSIST_TXT" | grep -cE '^[[:space:]]*-[aw][ ]')
    printf '%s\n' "$AUD_PERSIST_TXT" | grep -qE '^[[:space:]]*-e[[:space:]]+2' && [ $AUD_READ -eq 0 ] && AUD_IMMUTABLE=2
    local r id name mitre rx why key st inL inP
    for r in "${AUDIT_BASELINE[@]}"; do
        id=${r%%|*}; local rest=${r#*|}; name=${rest%%|*}; rest=${rest#*|}; mitre=${rest%%|*}; rest=${rest#*|}
        key=${rest##*|}; rest=${rest%|*}; why=${rest##*|}; rx=${rest%|*}
        inL=0; inP=0
        printf '%s\n' "$AUD_LOADED_TXT" | grep -Eq -- "$rx" && inL=1
        printf '%s\n' "$AUD_PERSIST_TXT" | grep -Eq -- "$rx" && inP=1
        if [ $AUD_RUNNING -eq 0 ] || [ "$AUD_ENABLED" = 0 ] || [ "${KERNEL_AUDIT_OFF:-0}" -eq 1 ]; then st='Inactive'
        elif [ $AUD_READ -eq 1 ]; then
            if [ $inL -eq 1 ]; then st='OK'
            elif [ $inP -eq 1 ]; then st='Not loaded'
            else st='Missing'; fi
        else
            if [ $inP -eq 1 ]; then st='Persistent only'; else st='Missing'; fi
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$mitre" "$st" "$inL" "$inP" "$why" "$key" >> "$F_AR"
    done
    step OK "auditd installed: $AUD_INSTALLED, running: $AUD_RUNNING, enabled: ${AUD_ENABLED:-?}, loaded rules: $AUD_RULES_LOADED, persistent rules: $AUD_RULES_PERSIST"
}

# =====================================================================================================
#  4. Logging configuration (syslog daemon, journald, sshd, shell history, EDR / agents)
# =====================================================================================================
collect_config() {
    step STEP 'Logging configuration'
    SYSLOGD=''; SYSLOGD_RUN=0
    for p in rsyslogd syslog-ng syslogd; do proc_running "$p" && { SYSLOGD=$p; SYSLOGD_RUN=1; break; }; done
    [ -z "$SYSLOGD" ] && { have rsyslogd && SYSLOGD=rsyslogd; have syslog-ng && SYSLOGD=syslog-ng; }
    add_cfg 'Syslog daemon' "${SYSLOGD:-none}$( [ $SYSLOGD_RUN -eq 1 ] && echo ' (running)' || echo ' (not running)')" "$( [ $SYSLOGD_RUN -eq 1 ] && echo ok || { [ $SYSTEMD -eq 1 ] && echo warn || echo bad; } )"
    { cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; } > "$RAW/rsyslog.conf.txt"
    { cat /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf 2>/dev/null; } > "$RAW/syslog-ng.conf.txt"
    [ -s "$RAW/syslog-ng.conf.txt" ] || rm -f "$RAW/syslog-ng.conf.txt"
    add_cfg 'Journald storage' "$JOURNAL_STORAGE" "$( [ $JOURNAL_PERSIST -eq 1 ] && echo ok || { [ $SYSTEMD -eq 1 ] && echo warn || echo na; } )"
    add_cfg 'auditd' "installed: $AUD_INSTALLED, running: $AUD_RUNNING, service: $AUD_SVC / $AUD_SVC_EN, enabled flag: ${AUD_ENABLED:-unknown}" "$( [ $AUD_RUNNING -eq 1 ] && echo ok || echo bad )"
    add_cfg 'auditd rules loaded / persistent' "$AUD_RULES_LOADED / $AUD_RULES_PERSIST$( [ $AUD_IMMUTABLE -ge 1 ] && echo ' (immutable -e 2)')" "$( [ "$AUD_RULES_LOADED" -gt 0 ] && echo ok || echo bad )"
    if [ -r "$AUD_CONF" ]; then
        local k
        for k in num_logs max_log_file max_log_file_action space_left_action admin_space_left_action disk_full_action disk_error_action write_logs log_format; do
            local v; v=$(audv "$k"); [ -z "$v" ] && continue
            local s=ok
            case "$k:$v" in
                disk_full_action:[Ii][Gg][Nn]*|disk_full_action:[Ss][Uu][Ss]*|disk_error_action:[Ii][Gg][Nn]*|max_log_file_action:[Ii][Gg][Nn]*|max_log_file_action:[Ss][Uu][Ss]*|space_left_action:[Ii][Gg][Nn]*|admin_space_left_action:[Ii][Gg][Nn]*) s=warn ;;
                write_logs:[Nn][Oo]) s=bad ;;
            esac
            add_cfg "auditd.conf $k" "$v" "$s"
        done
    fi
    add_cfg 'Kernel audit (boot parameter)' "$( [ $KERNEL_AUDIT_OFF -eq 1 ] && echo 'audit=0 - kernel auditing disabled at boot' || (grep -qw 'audit=1' /proc/cmdline 2>/dev/null && echo 'audit=1' || echo 'default'))" "$( [ $KERNEL_AUDIT_OFF -eq 1 ] && echo bad || echo ok )"
    # sshd
    SSHD_LOGLEVEL=''; SSHD_ROOT=''; SSHD_PWAUTH=''; SSHD_AKF='.ssh/authorized_keys .ssh/authorized_keys2'; SSHD_EMPTY=''
    if have sshd || [ -x /usr/sbin/sshd ]; then
        local sx=/usr/sbin/sshd; have sshd && sx=$(command -v sshd)
        local t; [ $IS_ROOT -eq 1 ] && t=$(run_to 15 "$sx" -T 2>/dev/null)
        if [ -n "$t" ]; then printf '%s\n' "$t" > "$RAW/sshd_T.txt"
        else t=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*#' | tr 'A-Z' 'a-z'); printf '%s\n' "$t" > "$RAW/sshd_config.txt"; fi
        sv() { printf '%s\n' "$t" | awk -v k="$1" 'tolower($1)==k { $1=""; sub(/^ /,""); print; exit }'; }
        SSHD_LOGLEVEL=$(sv loglevel); SSHD_ROOT=$(sv permitrootlogin); SSHD_PWAUTH=$(sv passwordauthentication); SSHD_EMPTY=$(sv permitemptypasswords)
        local akf; akf=$(sv authorizedkeysfile); [ -n "$akf" ] && SSHD_AKF="$akf"
        [ -z "$SSHD_LOGLEVEL" ] && SSHD_LOGLEVEL=info; [ -z "$SSHD_AKF" ] && SSHD_AKF='.ssh/authorized_keys .ssh/authorized_keys2'
        local ll; ll=$(echo "$SSHD_LOGLEVEL" | tr 'a-z' 'A-Z')
        add_cfg 'sshd LogLevel' "$ll" "$(case "$ll" in VERBOSE|DEBUG*) echo ok ;; *) echo warn ;; esac)"
        add_cfg 'sshd PermitRootLogin' "${SSHD_ROOT:-default}" "$(case "$SSHD_ROOT" in yes) echo warn ;; *) echo ok ;; esac)"
        add_cfg 'sshd PasswordAuthentication' "${SSHD_PWAUTH:-default}" "$(case "$SSHD_PWAUTH" in no) echo ok ;; *) echo warn ;; esac)"
    fi
    # shell history configuration
    HIST_TIME=0; HIST_OFF_FILES=''
    local sh_files; sh_files=$(ls /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /etc/environment /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /etc/zsh/zshrc /etc/zshrc 2>/dev/null)
    local f
    for f in $sh_files; do
        grep -Eq '^[^#]*HISTTIMEFORMAT=' "$f" 2>/dev/null && case "$f" in /etc/*) HIST_TIME=1 ;; esac
        grep -Eq '^[^#]*(HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0([^0-9]|$)|HISTFILESIZE=0([^0-9]|$)|set[[:space:]]+\+o[[:space:]]+history|HISTCONTROL=.*ignorespace.*HISTIGNORE=.\*)' "$f" 2>/dev/null && HIST_OFF_FILES="$HIST_OFF_FILES $f"
    done
    add_cfg 'Shell history timestamps (HISTTIMEFORMAT, global)' "$( [ $HIST_TIME -eq 1 ] && echo set || echo 'not set')" "$( [ $HIST_TIME -eq 1 ] && echo ok || echo warn )"
    HIST_NULL=''
    for f in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
        [ -L "$f" ] && [ "$(readlink "$f")" = /dev/null ] && HIST_NULL="$HIST_NULL $f"
    done
    # process accounting
    PACCT=0; { [ -s /var/log/account/pacct ] || [ -s /var/account/pacct ] || [ -s /var/log/pacct ]; } && PACCT=1
    add_cfg 'Process accounting (psacct / acct)' "$( [ $PACCT -eq 1 ] && echo active || echo 'not active')" "$( [ $PACCT -eq 1 ] && echo ok || echo na )"
    # ld.so.preload
    PRELOAD=''; [ -s /etc/ld.so.preload ] && PRELOAD=$(grep -v '^[[:space:]]*#' /etc/ld.so.preload 2>/dev/null | tr '\n' ' ')
    add_cfg '/etc/ld.so.preload' "${PRELOAD:-empty / absent}" "$( [ -n "$PRELOAD" ] && echo bad || echo ok )"
    # Sysmon for Linux, EDR and log shippers
    SYSMON=0; { proc_running sysmon || [ -x /opt/sysmon/sysmon ]; } && SYSMON=1
    local agents=(
        'falcon-sensor|EDR|CrowdStrike Falcon|/opt/CrowdStrike'
        'mdatp|EDR|Microsoft Defender for Endpoint|/opt/microsoft/mdatp'
        'wdavdaemon|EDR|Microsoft Defender for Endpoint|'
        'traps_pmd|EDR|Palo Alto Cortex XDR|/opt/traps'
        'pmd|EDR|Palo Alto Cortex XDR|/opt/traps'
        's1-agent|EDR|SentinelOne|/opt/sentinelone'
        'sentinelone-agent|EDR|SentinelOne|'
        'cbagentd|EDR|VMware Carbon Black|/opt/carbonblack'
        'ds_agent|EDR|Trend Micro Deep Security|/opt/ds_agent'
        'xagt|EDR|Trellix / FireEye HX|/opt/fireeye'
        'elastic-endpoint|EDR|Elastic Defend|/opt/Elastic/Endpoint'
        'sysmon|EDR|Sysmon for Linux|/opt/sysmon'
        'osqueryd|Telemetry|osquery|'
        'auditbeat|Log forwarder|Elastic Auditbeat|'
        'filebeat|Log forwarder|Elastic Filebeat|'
        'elastic-agent|Log forwarder|Elastic Agent|/opt/Elastic/Agent'
        'fluent-bit|Log forwarder|Fluent Bit|'
        'td-agent|Log forwarder|Fluentd|'
        'fluentd|Log forwarder|Fluentd|'
        'nxlog|Log forwarder|NXLog|'
        'wazuh-agentd|Log forwarder|Wazuh agent|/var/ossec'
        'ossec-agentd|Log forwarder|OSSEC agent|/var/ossec'
        'qualys-cloud-agent|Telemetry|Qualys Cloud Agent|'
        'splunkd|Log forwarder|Splunk|'
        'audisp-remote|Log forwarder|auditd remote (audisp-remote)|'
        'otelcol-contrib|Log forwarder|OpenTelemetry collector|'
        'google_osconfig_agent|Telemetry|Google OS Config|'
        'amazon-cloudwatch-agent|Log forwarder|CloudWatch agent|'
        'mdsd|Log forwarder|Azure Monitor agent|'
    )
    EDR_COUNT=0; FWD_COUNT=0
    local a pn ty nm dir run
    for a in "${agents[@]}"; do
        IFS='|' read -r pn ty nm dir <<< "$a"
        run=0; proc_running "$pn" && run=1
        if [ $run -eq 1 ] || { [ -n "$dir" ] && [ -d "$dir" ]; }; then
            grep -q "	$nm	" "$F_AGENT" && continue
            printf '%s\t%s\t%s\n' "$ty" "$nm" "$( [ $run -eq 1 ] && echo running || echo 'installed, not running')" >> "$F_AGENT"
            [ $run -eq 1 ] && [ "$ty" = EDR ] && EDR_COUNT=$((EDR_COUNT+1))
            [ $run -eq 1 ] && [ "$ty" = 'Log forwarder' ] && [ "$pn" != splunkd ] && FWD_COUNT=$((FWD_COUNT+1))
        fi
    done
    step OK "syslog: ${SYSLOGD:-none} ($SYSLOGD_RUN), sshd LogLevel ${SSHD_LOGLEVEL:-n/a}, EDR running: $EDR_COUNT, Sysmon: $SYSMON"
}

# =====================================================================================================
#  5. SIEM forwarding (Splunk Universal Forwarder, syslog forwarding)
# =====================================================================================================
splunk_rx() {   # convert a Splunk monitor path to an anchored ERE
    printf '%s' "$1" | sed -e 's/\.\.\./QQDOTSQQ/g' -e 's/[][\.+?(){}|^$]/\\&/g' -e 's/\*/[^\/]*/g' -e 's/QQDOTSQQ/.*/g'
}
collect_siem() {
    step STEP 'SIEM forwarding'
    SPLUNK=0; SPLUNK_HOME=''; SPLUNK_VER=''; SPLUNK_RUN=0; SPLUNK_SERVERS=''; SPLUNK_DS=''; SPLUNK_ERR=0; SPLUNK_BLOCK=0; SPLUNK_JOURNALD=0
    local c
    for c in /opt/splunkforwarder /opt/splunk /usr/local/splunkforwarder /usr/local/splunk; do [ -d "$c/etc" ] && { SPLUNK_HOME=$c; break; }; done
    if [ -z "$SPLUNK_HOME" ] && proc_running splunkd; then
        local exe; exe=$(readlink "/proc/$(pgrep -x splunkd | head -1)/exe" 2>/dev/null); [ -n "$exe" ] && SPLUNK_HOME=${exe%/bin/splunkd}
    fi
    if [ -n "$SPLUNK_HOME" ]; then
        SPLUNK=1
        SPLUNK_VER=$(grep -E '^VERSION=' "$SPLUNK_HOME/etc/splunk.version" 2>/dev/null | cut -d= -f2)
        proc_running splunkd && SPLUNK_RUN=1
        local bt="$RAW/splunk_btool_inputs.txt"
        if [ -x "$SPLUNK_HOME/bin/splunk" ]; then
            SPLUNK_HOME="$SPLUNK_HOME" run_to 90 "$SPLUNK_HOME/bin/splunk" btool inputs list --debug --no-prompt > "$bt" 2>/dev/null
            SPLUNK_HOME="$SPLUNK_HOME" run_to 60 "$SPLUNK_HOME/bin/splunk" btool outputs list --debug --no-prompt > "$RAW/splunk_btool_outputs.txt" 2>/dev/null
        fi
        if [ ! -s "$bt" ] || ! grep -q '\[' "$bt"; then
            # manual merge: lowest precedence first, every line prefixed with its file (btool --debug format)
            : > "$bt"
            local f
            for f in "$SPLUNK_HOME"/etc/system/default/inputs.conf "$SPLUNK_HOME"/etc/apps/*/default/inputs.conf "$SPLUNK_HOME"/etc/apps/*/local/inputs.conf "$SPLUNK_HOME"/etc/system/local/inputs.conf; do
                [ -r "$f" ] && sed -e 's/\r$//' -e "s#^#$f #" "$f" >> "$bt"
            done
            : > "$RAW/splunk_btool_outputs.txt"
            for f in "$SPLUNK_HOME"/etc/system/default/outputs.conf "$SPLUNK_HOME"/etc/apps/*/*/outputs.conf "$SPLUNK_HOME"/etc/system/local/outputs.conf; do
                [ -r "$f" ] && sed -e 's/\r$//' -e "s#^#$f #" "$f" >> "$RAW/splunk_btool_outputs.txt"
            done
            add_wf 'Splunk btool' 'Fallback' 'btool not available - .conf files merged directly (local overrides default)'
        fi
        # stanzas -> splunk.tsv : stanza  disabled  index  sourcetype  whitelist  blacklist  file
        awk '
            { f=$1; $1=""; sub(/^[ \t]+/,""); line=$0 }
            line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/ { next }
            line ~ /^\[/ { st=line; gsub(/^\[|\][ \t]*$/,"",st); if (!(st in seen)) { seen[st]=1; order[++n]=st }; file[st]=f; next }
            st!="" { k=line; sub(/[ \t]*=.*/,"",k); v=line; sub(/^[^=]*=[ \t]*/,"",v)
                     if (k=="disabled") dis[st]=v; else if (k=="index") idx[st]=v; else if (k=="sourcetype") stp[st]=v
                     else if (k ~ /^whitelist/) wl[st]=(wl[st]==""?v:wl[st] "\036" v); else if (k ~ /^blacklist/) bl[st]=(bl[st]==""?v:bl[st] "\036" v)
                     if (k=="disabled" || k=="index" || k ~ /^(white|black)list/) file[st]=f }
            END { for (i=1;i<=n;i++) { s=order[i]; if (s !~ /^(monitor|batch|journald|tcp|udp|splunktcp|WinEventLog|script|fschange):/ && s !~ /^(monitor|batch|journald):\/\//) continue
                  if (s ~ /^(tcp|udp|splunktcp|WinEventLog|script|fschange)/) continue
                  d=dis[s]; d=(d ~ /^(1|true|True|TRUE|t|yes)$/)?"1":"0"
                  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s, d, idx[s], stp[s], wl[s], bl[s], file[s] } }' "$bt" > "$F_SP"
        grep -q '^journald://' "$F_SP" && awk -F'\t' '$1 ~ /^journald:/ && $2=="0" { f=1 } END { exit !f }' "$F_SP" && SPLUNK_JOURNALD=1
        SPLUNK_SERVERS=$(awk '{ $1=""; sub(/^ +/,"") } /^server[ \t]*=/ { sub(/^server[ \t]*=[ \t]*/,""); print }' "$RAW/splunk_btool_outputs.txt" 2>/dev/null | sort -u | tr '\n' ' ')
        SPLUNK_DS=$(cat "$SPLUNK_HOME"/etc/system/local/deploymentclient.conf "$SPLUNK_HOME"/etc/apps/*/*/deploymentclient.conf 2>/dev/null | awk -F= '/^[ \t]*targetUri/ { gsub(/[ \t]/,"",$2); print $2; exit }')
        local sl="$SPLUNK_HOME/var/log/splunk/splunkd.log"
        if [ -r "$sl" ]; then
            tail -n 20000 "$sl" > "$W/splunkd.tail"
            SPLUNK_ERR=$(grep -cE ' (ERROR|WARN) +(TcpOutputProc|TcpOutputFd|AutoLoadBalancedConnectionStrategy)' "$W/splunkd.tail")
            SPLUNK_BLOCK=$(grep -cE 'blocked|Queue is full|paused' "$W/splunkd.tail")
            grep -E ' (ERROR|WARN) ' "$W/splunkd.tail" | tail -n 200 > "$RAW/splunkd_errors_tail.txt"
        fi
    fi
    # per log file forwarding status -> splunk_files.tsv : path  status  rule
    local kind name path rest
    while IFS=$'\037' read -r kind name path rest; do
        local status='NotCollected' rule='no monitor stanza covers this file'
        if [ $SPLUNK -eq 0 ]; then status='None'; rule=''
        elif [ "$kind" = journal ]; then
            if [ $SPLUNK_JOURNALD -eq 1 ]; then status='Forwarded'; rule='journald:// input'
            else status='NotCollected'; rule='no journald:// input (journal is only collected through rsyslog files)'; fi
        else
            local st dis idx stp wl bl sf
            while IFS=$'\037' read -r st dis idx stp wl bl sf; do
                case "$st" in monitor://*|batch://*) ;; *) continue ;; esac
                local sp=${st#*://}; [ "$sp" != / ] && sp=${sp%/}; local rx; rx=$(splunk_rx "$sp")
                printf '%s\n' "$path" | grep -Eq "^${rx}(/.*)?\$" || continue
                local excl=''
                if [ -n "$wl" ]; then
                    local ok=0 w; IFS=$'\036' read -ra _w <<< "$wl"
                    for w in "${_w[@]}"; do printf '%s\n' "$path" | grep -Pq -- "$w" 2>/dev/null && ok=1 || { printf '%s\n' "$path" | grep -Eq -- "$w" 2>/dev/null && ok=1; }; done
                    [ $ok -eq 0 ] && excl="whitelist '${wl//$'\036'/ || }' does not match"
                fi
                if [ -n "$bl" ] && [ -z "$excl" ]; then
                    local b; IFS=$'\036' read -ra _b <<< "$bl"
                    for b in "${_b[@]}"; do { printf '%s\n' "$path" | grep -Pq -- "$b" 2>/dev/null || printf '%s\n' "$path" | grep -Eq -- "$b" 2>/dev/null; } && excl="blacklist '$b' matches"; done
                fi
                if [ "$dis" = 1 ]; then excl="stanza disabled"; fi
                if [ -z "$excl" ]; then status='Forwarded'; rule="[$st] index=${idx:-default} sourcetype=${stp:-auto} ($sf)"; break
                else status='Filtered'; rule="[$st] $excl ($sf)"; fi
            done < <(tr '\t' '\037' < "$F_SP")
        fi
        printf '%s\t%s\t%s\n' "$path" "$status" "$(clean "$rule")" >> "$F_SPF"
    done < <(awk -F'\t' '$4!="Missing"' "$F_LOGS" | tr '\t' '\037')
    # other forwarding paths
    SYSLOG_FWD=$(cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -oE '(@@?\(?[a-zA-Z0-9_.:\[\]-]+|omfwd[^)]*target="[^"]+"|omrelp[^)]*target="[^"]+")' | sed 's/.*target="//; s/"$//' | sort -u | tr '\n' ' ')
    local sng; sng=$(cat /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -oE '(network|tcp|udp|syslog)\([[:space:]]*"[^"]+"' | sed 's/.*"\(.*\)"/\1/' | sort -u | tr '\n' ' ')
    [ -n "$sng" ] && SYSLOG_FWD="$SYSLOG_FWD $sng"
    AUDISP_REMOTE=0
    for c in /etc/audit/plugins.d/au-remote.conf /etc/audisp/plugins.d/au-remote.conf; do grep -Eq '^[[:space:]]*active[[:space:]]*=[[:space:]]*yes' "$c" 2>/dev/null && AUDISP_REMOTE=1; done
    add_cfg 'Syslog forwarding targets' "${SYSLOG_FWD:-none}" "$( [ -n "$(echo $SYSLOG_FWD)" ] && echo ok || echo na )"
    add_cfg 'auditd remote (au-remote)' "$( [ $AUDISP_REMOTE -eq 1 ] && echo active || echo 'not active')" "$( [ $AUDISP_REMOTE -eq 1 ] && echo ok || echo na )"
    if [ $SPLUNK -eq 1 ]; then step OK "Splunk $SPLUNK_VER at $SPLUNK_HOME (running: $SPLUNK_RUN), $(grep -c . "$F_SP") input stanza(s)"
    else step OK "No Splunk forwarder found; syslog forwarding: ${SYSLOG_FWD:-none}"; fi
}

# =====================================================================================================
#  6. Tampering evidence
# =====================================================================================================
near_shutdown() {  # near_shutdown EPOCH -> 0 if within 10 min before a boot / shutdown record
    awk -F'\t' -v t="$1" '$1>=t-120 && $1<=t+600 { f=1 } END { exit !f }' "$F_BOOT"
}
collect_tamper() {
    step STEP 'Tampering evidence'
    # deleted log files still held open by a process
    DELETED_OPEN=''
    if [ $IS_ROOT -eq 1 ]; then
        DELETED_OPEN=$(find /proc/[0-9]*/fd -maxdepth 1 -type l -printf '%p -> %l\n' 2>/dev/null | grep -E -- '-> /(var/log|var/spool|run/log)/.*\(deleted\)' | head -n 50)
        if [ -n "$DELETED_OPEN" ]; then
            local d pid comm
            while IFS= read -r d; do
                pid=$(printf '%s' "$d" | cut -d/ -f3); comm=$(cat "/proc/$pid/comm" 2>/dev/null)
                add_event "$NOW" Critical "$comm (pid $pid)" clear 'Log file deleted while still open' "${d#*-> }"
            done <<< "$DELETED_OPEN"
        fi
    fi
    # immutable / append-only attributes on logs
    LOG_IMMUTABLE=''
    if have lsattr; then
        LOG_IMMUTABLE=$(lsattr -d /var/log/* /var/log/audit/* 2>/dev/null | awk '$1 ~ /i/ { print $2 }' | head -n 20 | tr '\n' ' ')
    fi
    # auditd events in audit.log (config changes, daemon end, disabled)
    if [ -r "$AUD_LOG" ]; then
        for f in $(rotated_set "$AUD_LOG"); do catf "$f"; done |
          grep -E 'type=(CONFIG_CHANGE|DAEMON_END|DAEMON_ABORT|DAEMON_CONFIG|SERVICE_STOP)' |
          awkx '{ t=ts($0); kind=""; title=""; sev="Medium"; det=""
                  if ($0 ~ /type=CONFIG_CHANGE/ && $0 ~ /op=remove_rule|op="remove_rule"/) { kind="policy"; title="Audit rule removed"; sev="High" }
                  else if ($0 ~ /type=CONFIG_CHANGE/ && $0 ~ /audit_enabled=0/) { kind="policy"; title="Auditing disabled (audit_enabled=0)"; sev="Critical" }
                  else if ($0 ~ /type=CONFIG_CHANGE/ && $0 ~ /op=(set|"set")/ && $0 ~ /audit_enabled=/) { kind="policy"; title="Audit enabled flag changed"; sev="Medium" }
                  else if ($0 ~ /type=CONFIG_CHANGE/ && $0 ~ /list=|op=(add_rule|"add_rule")/) { kind="policy"; title="Audit rules changed"; sev="Info" }
                  else if ($0 ~ /type=DAEMON_ABORT/) { kind="svc"; title="auditd aborted"; sev="High" }
                  else if ($0 ~ /type=DAEMON_END/) { kind="svc"; title="auditd stopped"; sev="Medium" }
                  else if ($0 ~ /type=SERVICE_STOP/ && $0 ~ /unit=(auditd|rsyslog|syslog|systemd-journald)/) { kind="svc"; title="Logging service stopped"; sev="Medium" }
                  else next
                  if (match($0,/auid=[0-9]+/)) det=substr($0,RSTART,RLENGTH); if (match($0,/unit=[a-z-]+/)) det=det " " substr($0,RSTART,RLENGTH)
                  if (match($0,/(key|op)=[^ ]+/)) det=det " " substr($0,RSTART,RLENGTH)
                  printf "%s\t%s\taudit.log\t%s\t%s\t%s\n", t, sev, kind, title, det }' | tail -n 500 > "$W/ev_audit.tsv"
        # drop service stops that are part of a shutdown
        while IFS=$'\037' read -r t sev src kind title det; do
            if [ "$kind" = svc ] && near_shutdown "$t"; then continue; fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$sev" "$src" "$kind" "$title" "$det" >> "$F_EV"
        done < <(tr '\t' '\037' < "$W/ev_audit.tsv")
    fi
    # syslog / journal messages
    local rx='(rsyslogd.*(exiting on signal|was HUPed)|auditd.*(stopped|Shutting down|exiting)|Stopp(ed|ing) (Security Auditing Service|System Logging Service|Journal Service)|systemd-journald.*(Journal stopped|Received SIGTERM)|Time has been changed|[Cc]lock (step|jump|was stepped)|System clock wrong|time stepped|kernel: audit: (audit_enabled|backlog limit exceeded|audit_lost)|audit: kauditd hold queue overflow|Vacuuming done|Deleted archived journal|syslog-ng.*(shutting down|Termination))'
    {
        if [ -n "$SYS_LOG" ] && [ -r "$SYS_LOG" ]; then for f in $(rotated_set "$SYS_LOG"); do catf "$f" | grep -E -m 2000 "$rx"; done
        elif [ $SYSTEMD -eq 1 ] && have journalctl; then run_to 180 journalctl -q --no-pager -o short-iso 2>/dev/null | grep -E -m 5000 "$rx"; fi
    } | awkx '{ t=ts($0); if (t<=0) next; kind="svc"; sev="Medium"; title=""
              if ($0 ~ /Time has been changed|[Cc]lock (step|jump|was stepped)|System clock wrong|time stepped/) { kind="time"; title="System time changed"; sev="Low" }
              else if ($0 ~ /backlog limit exceeded|audit_lost|hold queue overflow/) { kind="lost"; title="Audit events lost (kernel backlog)"; sev="High" }
              else if ($0 ~ /audit_enabled/) { kind="policy"; title="Kernel audit enabled flag changed"; sev="High" }
              else if ($0 ~ /Vacuuming done|Deleted archived journal/) { kind="other"; title="Journal files deleted (vacuum / rotation)"; sev="Info" }
              else if ($0 ~ /rsyslogd|System Logging Service|syslog-ng/) title="Syslog daemon stopped / restarted"
              else if ($0 ~ /auditd|Security Auditing/) title="auditd stopped"
              else if ($0 ~ /journald|Journal Service/) title="journald stopped"
              msg=$0; sub(/^[^ ]+ +[^ ]+ +[^ ]+ +/,"",msg); if (length(msg)>220) msg=substr(msg,1,220)
              printf "%s\t%s\tsyslog\t%s\t%s\t%s\n", t, sev, kind, title, msg }' > "$W/ev_sys.tsv"
    while IFS=$'\037' read -r t sev src kind title det; do
        if [ "$kind" = svc ] && near_shutdown "$t"; then continue; fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$sev" "$src" "$kind" "$title" "$det" >> "$F_EV"
    done < <(tail -n 1000 "$W/ev_sys.tsv" | tr '\t' '\037')
    while IFS=$'\037' read -r t k; do [ "$k" = boot ] && add_event "$t" Info wtmp boot 'System boot' ''; done < <(sort -u "$F_BOOT" | tr '\t' '\037')
    step OK "$(awk -F'\t' '$4!="boot"' "$F_EV" | grep -c .) tampering-relevant event(s)"
}

# =====================================================================================================
#  7. Privileged access, accounts and logons
# =====================================================================================================
collect_access() {
    step STEP 'Privileged access and logons'
    cp /etc/passwd "$RAW/passwd.txt" 2>/dev/null; cp /etc/group "$RAW/group.txt" 2>/dev/null
    # users.tsv : user uid gid home shell login(1/0) pwstate lastchg_epoch
    local shadow=''; [ -r /etc/shadow ] && shadow=/etc/shadow
    awk -F: -v S="$shadow" '
        BEGIN { if (S!="") while ((getline l < S) > 0) { split(l,a,":"); pw[a[1]]=a[2]; lc[a[1]]=a[3] } }
        { u=$1; sh=$7; login=(sh ~ /(nologin|false|sync|shutdown|halt)$/ || sh=="")?0:1
          st="unknown"; if (S!="") { p=pw[u]; if (p=="") st="EMPTY"; else if (p ~ /^[!*]/ || p=="!!") st=(p ~ /^![$]/)?"locked (hash kept)":"locked / no password"; else if (p ~ /^\$/) st="set"; else st="other" }
          c=(lc[u]!="")?lc[u]*86400:""
          printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", u, $3, $4, $6, sh, login, st, c }' /etc/passwd > "$F_USERS"
    # group members (secondary + primary)
    grp_members() {  # grp_members GROUPNAME -> user list
        local gid; gid=$(awk -F: -v g="$1" '$1==g { print $3 }' /etc/group)
        { awk -F: -v g="$1" '$1==g { n=split($4,a,","); for (i=1;i<=n;i++) if (a[i]!="") print a[i] }' /etc/group
          [ -n "$gid" ] && awk -F: -v g="$gid" '$4==g { print $1 }' /etc/passwd; } | sort -u
    }
    # sudoers
    SUDOERS_TXT=''
    if [ -r /etc/sudoers ]; then
        local f; local files=(/etc/sudoers)
        for f in /etc/sudoers.d/*; do case "$(basename "$f")" in *.*|*~) continue ;; esac; [ -f "$f" ] && files+=("$f"); done
        for f in "${files[@]}"; do
            SUDOERS_TXT="$SUDOERS_TXT$(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$f" 2>/dev/null | grep -vE '^[[:space:]]*(#[^i]|#$|$)' | grep -vE '^[[:space:]]*#include' | sed "s#^#$f: #")"$'\n'
        done
        printf '%s' "$SUDOERS_TXT" > "$RAW/sudoers_effective.txt"
    fi
    # privileged.tsv : account  how  detail
    awk -F'\t' '$2==0 { printf "%s\tUID 0\troot-equivalent account\n", $1 }' "$F_USERS" >> "$F_PRIV"
    local g
    for g in sudo wheel admin root; do
        grep -q "^$g:" /etc/group || continue
        local m; for m in $(grp_members "$g"); do printf '%s\tgroup %s\tmember of the %s group\n' "$m" "$g" "$g" >> "$F_PRIV"; done
    done
    if [ -n "$SUDOERS_TXT" ]; then
        printf '%s\n' "$SUDOERS_TXT" | awk '
            { src=$1; sub(/:$/,"",src); $1=""; sub(/^ +/,"") }
            /^(Defaults|Cmnd_Alias|Host_Alias|Runas_Alias|User_Alias)/ { if ($1=="User_Alias") { a=$0; sub(/^User_Alias[ \t]+/,"",a); split(a,p,"="); gsub(/[ \t]/,"",p[1]); ua[p[1]]=p[2] }; next }
            NF>=2 && $0 ~ /=/ { who=$1; rest=$0; sub(/^[^ \t]+[ \t]+/,"",rest)
                cmd=rest; sub(/^[^=]*=[ \t]*/,"",cmd); np=(cmd ~ /NOPASSWD/)?"NOPASSWD ":""; cmds=cmd; gsub(/(NOPASSWD|PASSWD|SETENV|NOEXEC|EXEC|LOG_INPUT|LOG_OUTPUT):[ \t]*/,"",cmds); gsub(/\([^)]*\)[ \t]*/,"",cmds)
                full=(cmds ~ /(^|[ ,])ALL([ ,]|$)/ || cmds ~ /\/(ba|z|da|k|c|tc)?sh([ ,]|$)/ || cmds ~ /(vi|vim|less|more|find|awk|python[0-9.]*|perl|env|tee|cp|chmod|chown)([ ,]|$)/)?1:0
                if (who in ua) { n=split(ua[who],m,","); for (i=1;i<=n;i++) { gsub(/[ \t]/,"",m[i]); printf "%s\tsudoers (%s)\t%s%s -> %s\n", m[i], src, np, (full?"full root":"limited"), cmds } }
                else printf "%s\tsudoers (%s)\t%s%s -> %s\n", who, src, np, (full?"full root":"limited"), cmds }' > "$W/sudo_rules.tsv"
        while IFS=$'\037' read -r who how det; do
            case "$who" in
                %*) local gn=${who#%}; gn=${gn#:}; local m
                    for m in $(grp_members "$gn"); do printf '%s\t%s via %%%s\t%s\n' "$m" "$how" "$gn" "$det" >> "$F_PRIV"; done
                    printf '%s\t%s\t%s (group, %s member(s))\n' "$who" "$how" "$det" "$(grp_members "$gn" | grep -c .)" >> "$F_PRIV" ;;
                *) printf '%s\t%s\t%s\n' "$who" "$how" "$det" >> "$F_PRIV" ;;
            esac
        done < <(tr '\t' '\037' < "$W/sudo_rules.tsv")
    fi
    # SSH authorized keys : user  file  keys  mtime  options/comment
    local u uid gid home shell login pw lc
    while IFS=$'\037' read -r u uid gid home shell login pw lc; do
        [ -d "$home" ] || continue
        local p
        for p in $SSHD_AKF; do
            case "$p" in none) continue ;; esac
            p=${p//%h/$home}; p=${p//%u/$u}; p=${p//%%/%}; case "$p" in /*) ;; *) p="$home/$p" ;; esac
            [ -f "$p" ] || continue
            local n mt cm
            n=$(grep -cvE '^[[:space:]]*(#|$)' "$p" 2>/dev/null); mt=$(fmtime "$p")
            cm=$(grep -vE '^[[:space:]]*(#|$)' "$p" 2>/dev/null | awk '{ c=$NF; o=""; if ($1 !~ /^(ssh-|ecdsa-|sk-)/) o=" [options: " substr($1,1,40) "]"; printf "%s%s; ", c, o }' | cut -c1-400)
            printf '%s\t%s\t%s\t%s\t%s\n' "$u" "$p" "${n:-0}" "$mt" "$cm" >> "$F_KEYS"
        done
    done < <(tr '\t' '\037' < "$F_USERS")
    # current sessions
    who 2>/dev/null | awk '{ host=$NF; if (host !~ /^\(/) host=""; gsub(/[()]/,"",host); printf "%s\t%s\t%s %s\t%s\n", $1, $2, $3, $4, host }' > "$F_SESS"
    # ---- logons: wtmp (USER_PROCESS records) + auth log (Accepted ...)
    : > "$W/logon_raw.tsv"   # epoch user source tty method
    if have utmpdump && [ -r /var/log/wtmp ]; then
        for f in $(rotated_set /var/log/wtmp); do catf "$f" > "$W/utmp.tmp"; utmpdump "$W/utmp.tmp" 2>/dev/null; done |
          awkx -F'] \\[' '{ ty=$1; gsub(/[\[\] ]/,"",ty); if (ty!=7) next; u=$4; gsub(/ +$/,"",u); tty=$5; gsub(/ +$/,"",tty); hst=$6; gsub(/ +$/,"",hst); ip=$7; gsub(/[ \]]+$/,"",ip)
                  t=$8; gsub(/[\[\]]/,"",t); t=ts(t); if (t<=0 || u=="") next; if (ip=="0.0.0.0" || ip=="") ip=hst; if (ip=="") ip="local"
                  printf "%s\t%s\t%s\t%s\twtmp\n", t, u, ip, tty }' >> "$W/logon_raw.tsv"
    fi
    if [ -n "$AUTH_LOG" ] && [ -r "$AUTH_LOG" ]; then
        for f in $(rotated_set "$AUTH_LOG"); do catf "$f"; done > "$W/auth_all.txt"
    elif [ $SYSTEMD -eq 1 ] && have journalctl && [ $IS_ROOT -eq 1 ]; then
        run_to 180 journalctl -q --no-pager -o short-iso _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service + SYSLOG_FACILITY=4 + SYSLOG_FACILITY=10 2>/dev/null > "$W/auth_all.txt"
        add_wf 'Auth history source' 'Journal' 'no auth log file - SSH / sudo / account events read from the journal'
    else : > "$W/auth_all.txt"; fi
    awkx '
        / sshd\[[0-9]+\]: Accepted / { t=ts($0); if (t<=0) next; m=$0; sub(/.*Accepted /,"",m); split(m,a," "); meth=a[1]; u=a[3]; ip=a[5]
            printf "%s\t%s\t%s\tssh\tauth:%s\n", t, u, ip, meth >> LOG; next }
        / sshd\[[0-9]+\]: (Failed (password|publickey|keyboard-interactive|none)|Invalid user|Connection closed by (invalid|authenticating) user|Disconnected from (invalid|authenticating) user)/ {
            t=ts($0); if (t<=0) next; m=$0; u=""; ip=""
            if (m ~ /Failed /) { sub(/.*Failed [a-z-]+ for /,"",m); sub(/^invalid user /,"",m); split(m,a," "); u=a[1]; ip=a[3]; typ="ssh failed" }
            else if (m ~ /Invalid user/) { sub(/.*Invalid user /,"",m); split(m,a," "); u=a[1]; ip=a[3]; if (u=="from") { u="(empty)"; ip=a[2] }; typ="ssh invalid user" }
            else { sub(/.*(closed by|Disconnected from) (invalid|authenticating) user /,"",m); split(m,a," "); u=a[1]; ip=a[2]; typ="ssh pre-auth" }
            printf "%s\t%s\t%s\t%s\n", t, ip, u, typ >> FAIL; next }
        / (sudo|sudo\[[0-9]+\]): +[^ ]+ : / { t=ts($0); m=$0; sub(/.* sudo(\[[0-9]+\])?: +/,"",m); split(m,a," : "); u=a[1]; gsub(/ /,"",u)
            ok=(m ~ /COMMAND=/ && m !~ /(incorrect password|NOT in sudoers|command not allowed|authentication failure)/)?"ok":"denied"
            c=m; sub(/.*COMMAND=/,"",c); if (m !~ /COMMAND=/) c=m; if (length(c)>200) c=substr(c,1,200)
            r=m; sub(/.*USER=/,"",r); sub(/ .*/,"",r)
            printf "%s\t%s\t%s\t%s\t%s\n", t, u, ok, r, c >> SUDO; next }
        /pam_unix\(sudo:auth\): authentication failure/ { t=ts($0); u=$0; sub(/.*ruser=/,"",u); sub(/ .*/,"",u); if (u=="") { u=$0; sub(/.* user=/,"",u) }
            printf "%s\t%s\tdenied\t-\tauthentication failure\n", t, u >> SUDO; next }
        /pam_unix\(su(-l)?:session\): session opened for user / { t=ts($0); m=$0; sub(/.*session opened for user /,"",m); split(m,a," "); tgt=a[1]; sub(/\(.*/,"",tgt)
            by=m; sub(/.* by /,"",by); b2=by; sub(/\(.*/,"",by); if (by=="") by=b2; if (by=="") by="(unknown)"; printf "%s\t%s\tok\t%s\tsu\n", t, by, tgt >> SUDO; next }
        /(useradd|adduser)(\[[0-9]+\])?: new user: / { t=ts($0); m=$0; sub(/.*name=/,"",m); sub(/[, ].*/,"",m); d=$0; sub(/.*new user: /,"",d)
            printf "%s\taccount created\t%s\t\t%s\tauth log\n", t, m, d >> CHG; next }
        /(groupadd|addgroup)(\[[0-9]+\])?: new group: / { t=ts($0); m=$0; sub(/.*name=/,"",m); sub(/[, ].*/,"",m); printf "%s\tgroup created\t%s\t\t\tauth log\n", t, m >> CHG; next }
        /(usermod|gpasswd)(\[[0-9]+\])?: (add|user) .*to (shadow )?group/ { if ($0 ~ /shadow group/) next; t=ts($0); m=$0; u=m; sub(/.*(add|user) .?/,"",u); sub(/.? (to|added).*/,"",u); gsub(/'"'"'/,"",u)
            g=m; sub(/.*group .?/,"",g); sub(/'"'"'.*/,"",g); sub(/ .*/,"",g); printf "%s\tadded to group\t%s\t%s\t%s\tauth log\n", t, u, g, "" >> CHG; next }
        /(userdel|deluser)(\[[0-9]+\])?: (delete user|removed user)/ { t=ts($0); m=$0; sub(/.*user .?/,"",m); sub(/'"'"'.*/,"",m); sub(/ .*/,"",m); printf "%s\taccount deleted\t%s\t\t\tauth log\n", t, m >> CHG; next }
        /(passwd|chpasswd)(\[[0-9]+\])?: (pam_unix\(passwd:chauthtok\): )?password (changed|updated) for / { t=ts($0); m=$0; sub(/.*password (changed|updated) for /,"",m); sub(/ .*/,"",m)
            printf "%s\tpassword changed\t%s\t\t\tauth log\n", t, m >> CHG; next }
        /usermod(\[[0-9]+\])?: change user / { t=ts($0); m=$0; sub(/.*change user .?/,"",m); u=m; sub(/'"'"'.*/,"",u); d=m; sub(/^[^ ]+ /,"",d); printf "%s\taccount modified\t%s\t\t%s\tauth log\n", t, u, d >> CHG; next }
    ' -v LOG="$W/logon_raw.tsv" -v FAIL="$W/fail_raw.tsv" -v SUDO="$F_SUDO" -v CHG="$F_CHG" "$W/auth_all.txt"
    touch "$W/fail_raw.tsv"
    # btmp failed logons
    if have utmpdump && [ -r /var/log/btmp ]; then
        for f in $(rotated_set /var/log/btmp); do catf "$f" > "$W/utmp.tmp"; utmpdump "$W/utmp.tmp" 2>/dev/null; done |
          awkx -F'] \\[' '{ u=$4; gsub(/ +$/,"",u); hst=$6; gsub(/ +$/,"",hst); ip=$7; gsub(/[ \]]+$/,"",ip); if (ip=="0.0.0.0" || ip=="") ip=hst
                  t=$8; gsub(/[\[\]]/,"",t); t=ts(t); if (t<=0) next; printf "%s\t%s\t%s\tbtmp\n", t, ip, u }' >> "$W/fail_raw.tsv"
    fi
    # audit.log account management
    if [ -r "$AUD_LOG" ]; then
        for f in $(rotated_set "$AUD_LOG"); do catf "$f"; done | grep -E 'type=(ADD_USER|DEL_USER|ADD_GROUP|DEL_GROUP|USER_MGMT|GRP_MGMT|USER_CHAUTHTOK)' |
          awkx '{ t=ts($0); ty=$0; sub(/^type=/,"",ty); sub(/ .*/,"",ty); op=""; if (match($0,/op=[^ ]+/)) op=substr($0,RSTART+3,RLENGTH-3); gsub(/"/,"",op)
                  a=""; if (match($0,/(acct|id)=[^ ]+/)) a=substr($0,RSTART,RLENGTH); sub(/^(acct|id)=/,"",a); gsub(/"/,"",a)
                  by=""; if (match($0,/AUID="[^"]+"/)) by=substr($0,RSTART+6,RLENGTH-7); else if (match($0,/auid=[0-9]+/)) by=substr($0,RSTART,RLENGTH)
                  res=""; if (match($0,/res=[a-z]+/)) res=substr($0,RSTART+4,RLENGTH-4)
                  k=(ty=="ADD_USER")?"account created":(ty=="DEL_USER")?"account deleted":(ty=="ADD_GROUP")?"group created":(ty=="DEL_GROUP")?"group deleted":(ty=="USER_CHAUTHTOK")?"password changed":"account modified"
                  if (op ~ /add.*group|adding user to group|add-user-to-group/) k="added to group"
                  printf "%s\t%s\t%s\t\t%s %s\taudit (%s)\n", t, k, a, op, res, by }' >> "$F_CHG"
    fi
    # aggregate logons per user -> logons.tsv : user  logons  first  last  ips(ip=n;..)  methods  ttys
    awk -F'\t' '{ u=$2; n[u]++; if (!(u in f) || $1<f[u]) f[u]=$1; if ($1>l[u]) l[u]=$1
                  ipc[u SUBSEP $3]++; if (!((u SUBSEP $3) in seenip)) { seenip[u SUBSEP $3]=1; ips[u]=ips[u] SUBSEP $3 }
                  m=$5; if (!((u SUBSEP m) in seenm)) { seenm[u SUBSEP m]=1; meth[u]=meth[u] (meth[u]==""?"":", ") m }
                  tt=$4; sub(/[0-9]+$/,"",tt); if (!((u SUBSEP tt) in seent)) { seent[u SUBSEP tt]=1; tty[u]=tty[u] (tty[u]==""?"":", ") tt } }
         END { for (u in n) { s=""; k=split(substr(ips[u],2),a,SUBSEP); for (i=1;i<=k;i++) s=s (s==""?"":"; ") a[i] "=" ipc[u SUBSEP a[i]]
               printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", u, n[u], f[u], l[u], s, meth[u], tty[u] } }' "$W/logon_raw.tsv" | sort -t$'\t' -k4,4nr > "$F_LOGON"
    # failed per source -> failed.tsv : source  count  users(n)  sample users  types  first  last
    awk -F'\t' '{ s=$2; if (s=="") s="(local)"; n[s]++; if (!(s in f) || $1<f[s]) f[s]=$1; if ($1>l[s]) l[s]=$1
                  if (!((s SUBSEP $3) in su)) { su[s SUBSEP $3]=1; nu[s]++; if (nu[s]<=8) us[s]=us[s] (us[s]==""?"":", ") $3 }
                  if (!((s SUBSEP $4) in st)) { st[s SUBSEP $4]=1; ty[s]=ty[s] (ty[s]==""?"":", ") $4 } }
         END { for (s in n) printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s, n[s], nu[s], us[s], ty[s], f[s], l[s] }' "$W/fail_raw.tsv" | sort -t$'\t' -k2,2nr > "$F_FAIL"
    # lastlog (latest login per account, survives wtmp rotation)
    : > "$W/lastlog.tsv"
    if have lastlog; then
        lastlog 2>/dev/null | awk 'NR>1 && $0 !~ /Never logged in/ { u=$1; n=NF; d=$(n-4) " " $(n-3) " " $(n-2) " " $(n-1) " " $n; print u "\037" d }' |
        while IFS=$'\037' read -r u d; do printf '%s\t%s\n' "$u" "$(date -d "$d" +%s 2>/dev/null)"; done > "$W/lastlog.tsv"
    fi
    step OK "$(grep -c . "$F_USERS") accounts ($(awk -F'\t' '$6==1' "$F_USERS" | grep -c .) with login shell), $(cut -f1 "$F_PRIV" | sort -u | grep -c .) privileged, $(grep -c . "$F_LOGON") with logons, $(grep -c . "$F_FAIL") failed-logon source(s), $(grep -c . "$F_CHG") account change(s)"
}

# =====================================================================================================
#  8. Deep scan
# =====================================================================================================
deep_scan_log() {   # label path(s...) - reads all rotations oldest first
    local label="$1"; shift
    local files=() p f
    for p in "$@"; do while IFS= read -r f; do files+=("$f"); done < <(rotated_set "$p"); done
    [ ${#files[@]} -eq 0 ] && return
    step INFO "  reading $label (${#files[@]} file(s)) ..."
    local t0; t0=$(date +%s)
    local isaud=0; [ "$label" = 'Audit (auditd)' ] && isaud=1
    for f in "${files[@]}"; do catf "$f"; done | head -n "$DEEP_MAX" |
    awkx -v GAP="$GAP_MIN" -v AUD="$isaud" -v L="$label" -v MAX="$DEEP_MAX" -v FG="$F_GAPS" -v FH="$F_HIST" '
        { t=ts($0); if (t<=0) next; n++
          if (first==0) first=t
          if (prev>0) { d=t-prev
              if (d > GAP*60) printf "%s\ttime\t%s\t%s\t%d\n", L, prev, t, d/60 >> FG
              if (d < -300) { back++; if (back<=20) printf "%s\tbackwards\t%s\t%s\t%d\n", L, prev, t, -d/60 >> FG } }
          if (t>=prev || prev-t>300) prev=t
          if (t>last) last=t
          hr[int(t/3600)]++
          if (AUD && match($0,/audit\([0-9]+\.[0-9]+:[0-9]+\)/)) { s=substr($0,RSTART,RLENGTH); sub(/.*:/,"",s); sub(/\)/,"",s); s=s+0
              if (mx>0 && s>mx+1 && s-mx<5000000) { miss+=s-mx-1; sg++; if (sg<=200) printf "%s\tserial\t%s\t%s\t%d\n", L, pt, t, s-mx-1 >> FG }
              if (s>mx) { mx=s; pt=t } else if (mx-s>100000) { mx=s; pt=t } } }
        END { for (k in hr) printf "%s\t%s\t%s\n", L, k*3600, hr[k] >> FH
              printf "%s\t%d\t%s\t%s\t%d\t%d\t%d\t%s\n", L, n, first, last, back, miss, sg, (n>=MAX?"(truncated)":"-") }' >> "$F_DEEP"
    sed -i "\$s/\$/\t$(( $(date +%s) - t0 ))/" "$F_DEEP"
}

decode_history() {  # print "epoch<TAB>source<TAB>command" for shell histories
    local f u
    for f in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history /root/.ash_history /home/*/.ash_history /root/.sh_history /home/*/.sh_history; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        awk -v S="$f" '
            /^#[0-9]+$/ { t=substr($0,2); next }
            /^: [0-9]+:[0-9]+;/ { split($0,a,";"); tt=a[1]; sub(/^: /,"",tt); sub(/:.*/,"",tt); c=$0; sub(/^: [0-9]+:[0-9]+;/,"",c); printf "%s\t%s\t%s\n", tt, S, c; next }
            { printf "%s\t%s\t%s\n", (t==""?0:t), S, $0; t="" }' "$f"
    done
}

collect_deep() {
    step STEP 'Deep scan'
    [ -n "$AUTH_LOG" ] && [ -r "$AUTH_LOG" ] && deep_scan_log 'Authentication' "$AUTH_LOG"
    [ -n "$SYS_LOG" ] && [ -r "$SYS_LOG" ] && deep_scan_log 'System log' "$SYS_LOG"
    [ -r "$AUD_LOG" ] && deep_scan_log 'Audit (auditd)' "$AUD_LOG"
    if [ -z "$SYS_LOG" ] && [ $SYSTEMD -eq 1 ] && have journalctl; then
        step INFO '  reading systemd journal ...'
        local t0; t0=$(date +%s)
        run_to 900 journalctl -q --no-pager -o short-unix 2>/dev/null | head -n "$DEEP_MAX" > "$W/journal_all.txt"
        local tmp="$W/jdeep"; mkdir -p "$tmp"; cp "$W/journal_all.txt" "$tmp/journal"
        deep_scan_log 'systemd journal' "$tmp/journal"
    fi
    # journal integrity
    if [ $SYSTEMD -eq 1 ] && have journalctl && [ $JOURNAL_PERSIST -eq 1 ] && [ $IS_ROOT -eq 1 ]; then
        run_to 600 journalctl --verify 2>&1 | grep -iE 'fail|corrupt|bad' | head -n 50 > "$RAW/journal_verify.txt"
        JVERIFY=$(grep -c . "$RAW/journal_verify.txt")
    fi
    # wtmp integrity: zeroed / out-of-order records (log cleaners rewrite utmp records)
    WTMP_BAD=0; WTMP_ORDER=0
    if have utmpdump && [ -r /var/log/wtmp ]; then
        for f in $(rotated_set /var/log/wtmp); do catf "$f" > "$W/utmp.tmp"; utmpdump "$W/utmp.tmp" 2>/dev/null; done |
          awkx -F'] \\[' -v FG="$F_GAPS" '{ ty=$1; gsub(/[\[\] ]/,"",ty); t=$8; gsub(/[\[\]]/,"",t); e=ts(t); u=$4; gsub(/ +$/,"",u)
                 if (ty==0 || e<=86400) { bad++; next }
                 if (ty==7 && u=="") bad++
                 if (pe>0 && e < pe-120) { ord++; if (ord<=20) printf "wtmp\tbackwards\t%s\t%s\t%d\n", pe, e, (pe-e)/60 >> FG }
                 if (e>pe) pe=e }
               END { printf "%d %d\n", bad, ord }' > "$W/wtmp_check.txt"
        read -r WTMP_BAD WTMP_ORDER < "$W/wtmp_check.txt"
    fi
    # anti-logging commands
    DEEP_PATTERNS=0
    if [ -r "$PATTERN_FILE" ]; then
        grep -vE '^[[:space:]]*(#|$)' "$PATTERN_FILE" | awk -F'\t' 'NF>=2' > "$W/patterns.tsv"
        DEEP_PATTERNS=$(grep -c . "$W/patterns.tsv")
        {
            # auditd EXECVE records (arguments may be hex encoded)
            if [ -r "$AUD_LOG" ]; then
                for f in $(rotated_set "$AUD_LOG"); do catf "$f"; done | grep 'type=EXECVE' | head -n "$DEEP_MAX" |
                awkx 'function hx(s,  i,o,c) { o=""; for (i=1;i<length(s);i+=2) { c=index("0123456789ABCDEF",toupper(substr(s,i,1)))*16+index("0123456789ABCDEF",toupper(substr(s,i+1,1)))-17; if (c==0) c=32; o=o sprintf("%c",c) }; return o }
                      { t=ts($0); c=""; n=split($0,f," ")
                        for (i=1;i<=n;i++) if (f[i] ~ /^a[0-9]+=/) { v=f[i]; sub(/^a[0-9]+=/,"",v)
                            if (v ~ /^"/) { while (v !~ /"$/ && i<n) { i++; v=v " " f[i] }; gsub(/^"|"$/,"",v) } else if (v ~ /^[0-9A-Fa-f]+$/ && length(v)%2==0) v=hx(v)
                            c=c (c==""?"":" ") v }
                        printf "%s\taudit EXECVE\t%s\n", t, c }'
            fi
            decode_history
            awk -F'\t' '{ printf "%s\tsudo (auth log)\t%s\n", $1, $5 }' "$F_SUDO"
        } > "$W/cmd_sources.tsv"
        awk -F'\t' 'NR==FNR { name[++n]=$1; rx[n]=tolower($2); next }
                    { l=tolower($3); for (i=1;i<=n;i++) if (l ~ rx[i]) { c=$3; if (length(c)>400) c=substr(c,1,400); printf "%s\t%s\t%s\t%s\n", $1, $2, name[i], c; break } }' \
            "$W/patterns.tsv" "$W/cmd_sources.tsv" | sort -u | head -n 1000 > "$F_CMD"
    else
        add_wf 'Anti-logging command search' 'Skipped' 'anti-logging-patterns-linux.txt not found next to the script'
    fi
    add_wf 'Deep scan' 'Executed' "$(grep -c . "$F_DEEP") log(s) read completely, $DEEP_PATTERNS pattern(s)"
    step OK "deep scan: $(grep -c . "$F_DEEP") log(s), $(awk -F'\t' '$2=="serial"' "$F_GAPS" | grep -c .) audit serial gap(s), $(grep -c . "$F_CMD") anti-logging command(s)"
}

# =====================================================================================================
#  9. Evaluation: use cases, findings, score
# =====================================================================================================
# ID|Name|Tactic|MITRE|Roles|Key|sources (',' = all of, '|' = any of)
USECASES=(
'L01|SSH logons and brute force|Initial Access / Credential Access|T1021.004, T1110|ALL|1|log:auth,log:wtmp|log:btmp'
'L02|Logon history (who, when, from where)|Initial Access|T1078|ALL|1|log:wtmp|log:auth'
'L03|Privilege escalation with sudo / su|Privilege Escalation|T1548.003|ALL|1|log:auth'
'L04|Command execution|Execution|T1059.004|ALL|1|audit:A01|edr'
'L05|Local account creation and changes|Persistence|T1136.001, T1098|ALL|1|log:auth|audit:A02'
'L06|SSH authorized_keys persistence|Persistence|T1098.004|ALL|1|audit:A15|edr'
'L07|Cron persistence|Persistence|T1053.003|ALL|1|log:cron|log:syslog|log:journal,audit:A05|edr'
'L08|Systemd service persistence|Persistence|T1543.002|ALL|1|log:syslog|log:journal,audit:A06|edr'
'L09|Kernel module / rootkit loading|Persistence / Defense Evasion|T1547.006, T1014|ALL|1|log:kern|log:syslog|log:journal,audit:A07|edr'
'L10|Library preload hijacking|Defense Evasion|T1574.006|ALL|1|audit:A11|edr'
'L11|Log and audit tampering|Defense Evasion|T1070.002, T1562.012|ALL|1|audit:A09,audit:A10'
'L12|Time changes / timestomping|Defense Evasion|T1070.006|ALL|0|audit:A08'
'L13|Sudoers / PAM backdoors|Persistence / Credential Access|T1548.003, T1556.003|ALL|1|audit:A03,audit:A16'
'L14|SSH server configuration changes|Persistence|T1098.004|ALL|0|audit:A04'
'L15|Setuid / permission backdoors|Privilege Escalation|T1548.001, T1222.002|ALL|0|audit:A13|edr'
'L16|Process injection (ptrace)|Defense Evasion|T1055.008|ALL|0|audit:A14|edr'
'L17|Network connections / C2|Command and Control|T1071|ALL|0|edr|audit:A20'
'L18|Web shell activity|Persistence|T1505.003|WEB|1|log:web,audit:A01|edr'
'L19|Package / tool installation|Execution|T1072|ALL|0|log:pkg'
'L20|Interactive shell history|Execution|T1059.004|ALL|0|cfg:histtime'
'L21|SSH key based logon attribution|Lateral Movement|T1021.004|ALL|0|cfg:sshd_verbose,log:auth'
)
log_row() { awk -F'\t' -v k="$1" '$1==k && $4!="Missing" { print; exit }' "$F_LOGS"; }
src_check() {   # src_check TOKEN -> SRC_OK (0/1)  SRC_FILE  SRC_SPAN  SRC_WHY
    SRC_OK=0; SRC_FILE=''; SRC_SPAN=''; SRC_WHY=''
    local t="$1" row
    case "$t" in
        log:*) row=$(log_row "${t#log:}")
            if [ -z "$row" ]; then SRC_WHY='log not present'
            else IFS=$'\037' read -r _k _n SRC_FILE _st _nf _b _o _nw _l _r SRC_SPAN _rest <<< "$(printf '%s' "$row" | tr '\t' '\037')"
                 if [ "$_st" = OK ]; then SRC_OK=1; [ -n "$_nw" ] && [ $(( NOW - _nw )) -gt 604800 ] && SRC_WHY='no new events for more than 7 days'
                 else SRC_WHY="log $_st"; fi; fi ;;
        audit:*) row=$(awk -F'\t' -v k="${t#audit:}" '$1==k' "$F_AR")
            local st; st=$(printf '%s' "$row" | cut -f4)
            case "$st" in OK) SRC_OK=1 ;; 'Persistent only') SRC_OK=1; SRC_WHY='in rules files, not verified (not root)' ;; *) SRC_WHY="audit rule $(printf '%s' "$row" | cut -f2): ${st:-missing}" ;; esac
            if [ $SRC_OK -eq 1 ]; then row=$(log_row audit); [ -z "$row" ] && { SRC_OK=0; SRC_WHY='audit log missing'; }
                SRC_FILE=$(printf '%s' "$row" | cut -f3); SRC_SPAN=$(printf '%s' "$row" | cut -f11); fi ;;
        cfg:sshd_verbose) case "$(echo "$SSHD_LOGLEVEL" | tr a-z A-Z)" in VERBOSE|DEBUG*) SRC_OK=1 ;; *) SRC_WHY="sshd LogLevel ${SSHD_LOGLEVEL:-n/a} (needs VERBOSE)" ;; esac ;;
        cfg:histtime) [ $HIST_TIME -eq 1 ] && SRC_OK=1 || SRC_WHY='HISTTIMEFORMAT not set globally' ;;
        edr) [ "$EDR_COUNT" -gt 0 ] && { SRC_OK=1; SRC_FILE='EDR'; } || SRC_WHY='no EDR agent running' ;;
    esac
}
evaluate_usecases() {
    local u id name tac mitre roles key srcs
    for u in "${USECASES[@]}"; do
        IFS='|' read -r id name tac mitre roles key srcs <<< "$(printf '%s' "$u" | awk -F'|' '{ s=$7; for (i=8;i<=NF;i++) s=s "|" $i; printf "%s|%s|%s|%s|%s|%s|%s", $1,$2,$3,$4,$5,$6,s }')"
        if [ "$roles" != ALL ]; then case " $ROLES " in *" $roles "*) ;; *) continue ;; esac; fi
        local groups total=0 sat=0 detail='' ufiles='' span=''
        IFS=',' read -ra groups <<< "$srcs"
        local g
        for g in "${groups[@]}"; do
            total=$((total+1)); local alts; IFS='|' read -ra alts <<< "$g"; local ok=0 a why=''
            for a in "${alts[@]}"; do
                src_check "$a"
                if [ $SRC_OK -eq 1 ]; then ok=1; detail="$detail$a=OK${SRC_WHY:+ ($SRC_WHY)}; "; [ -n "$SRC_FILE" ] && ufiles="$ufiles$SRC_FILE|"
                    if [ -n "$SRC_SPAN" ] && { [ -z "$span" ] || [ "$SRC_SPAN" -lt "$span" ]; }; then span=$SRC_SPAN; fi; break
                else why="$why$a: $SRC_WHY / "; fi
            done
            [ $ok -eq 1 ] && sat=$((sat+1)) || detail="${detail}GAP (${why% / }); "
        done
        local status=Gap; [ $sat -eq $total ] && status=Covered; [ $sat -gt 0 ] && [ $sat -lt $total ] && status=Partial
        local siem='None' sd=''
        if [ $SPLUNK -eq 1 ] || [ -n "$(echo $SYSLOG_FWD)" ] || [ "$FWD_COUNT" -gt 0 ]; then
            local fw=0 nf=0 f st
            IFS='|' read -ra fl <<< "$ufiles"
            for f in "${fl[@]}"; do [ -z "$f" ] && continue; [ "$f" = EDR ] && continue; nf=$((nf+1))
                st=$(awk -F'\t' -v p="$f" '$1==p { print $2; exit }' "$F_SPF")
                if [ $SPLUNK -eq 1 ]; then [ "$st" = Forwarded ] && fw=$((fw+1)); sd="$sd$(basename "$f"): ${st:-NotCollected}; "
                else fw=$((fw+0)); sd="${sd}syslog / agent forwarding - not verifiable; "; fi
            done
            if [ $nf -eq 0 ]; then siem='n/a'; [ "$ufiles" = 'EDR|' ] && { siem='EDR'; sd='telemetry in the EDR console'; }
            elif [ $SPLUNK -eq 0 ]; then siem='Conditional'
            elif [ $fw -eq $nf ]; then siem='Forwarded'; elif [ $fw -gt 0 ]; then siem='Partial'; else siem='NotCollected'; fi
        fi
        [ "$status" = Gap ] && { siem='n/a'; sd=''; }
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$tac" "$mitre" "$status" "$(clean "${detail%; }")" "$siem" "$(clean "${sd%; }")" "$span" "$key" >> "$F_UC"
    done
}

AUDIT_RULE_SAMPLE() {
    case "$1" in
        A01) echo '-a always,exit -F arch=b64 -S execve,execveat -k exec ; -a always,exit -F arch=b32 -S execve,execveat -k exec' ;;
        A02) echo '-w /etc/passwd -p wa -k identity ; -w /etc/shadow -p wa -k identity ; -w /etc/group -p wa -k identity ; -w /etc/gshadow -p wa -k identity' ;;
        A03) echo '-w /etc/sudoers -p wa -k sudoers ; -w /etc/sudoers.d/ -p wa -k sudoers' ;;
        A04) echo '-w /etc/ssh/sshd_config -p wa -k sshd ; -w /etc/ssh/sshd_config.d/ -p wa -k sshd' ;;
        A05) echo '-w /etc/crontab -p wa -k cron ; -w /etc/cron.d/ -p wa -k cron ; -w /var/spool/cron/ -p wa -k cron' ;;
        A06) echo '-w /etc/systemd/system/ -p wa -k systemd ; -w /usr/lib/systemd/system/ -p wa -k systemd' ;;
        A07) echo '-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules ; -w /usr/sbin/insmod -p x -k modules ; -w /usr/sbin/modprobe -p x -k modules' ;;
        A08) echo '-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change ; -w /etc/localtime -p wa -k time-change' ;;
        A09) echo '-w /etc/audit/ -p wa -k auditconfig ; -w /var/log/audit/ -p wa -k auditlog ; -w /sbin/auditctl -p x -k audittools' ;;
        A10) echo '-w /var/log/wtmp -p wa -k logins ; -w /var/log/btmp -p wa -k logins ; -w /var/log/lastlog -p wa -k logins ; -w /var/run/utmp -p wa -k session' ;;
        A11) echo '-w /etc/ld.so.preload -p wa -k preload' ;;
        A12) echo '-w /usr/bin/sudo -p x -k priv_cmd ; -w /usr/bin/su -p x -k priv_cmd ; -w /usr/bin/passwd -p x -k priv_cmd' ;;
        A13) echo '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod' ;;
        A14) echo '-a always,exit -F arch=b64 -S ptrace -k ptrace' ;;
        A15) echo '-w /root/.ssh/ -p wa -k rootkey' ;;
        A16) echo '-w /etc/pam.d/ -p wa -k pam ; -w /etc/security/ -p wa -k pam' ;;
        A17) echo '-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=unset -k mounts' ;;
        A18) echo '-a always,exit -F arch=b64 -S open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access' ;;
        A19) echo '-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete' ;;
        A20) echo '-a always,exit -F arch=b64 -S connect -F a2!=110 -k network_connect (high volume - consider EDR instead)' ;;
        A21) echo '-w /etc/hosts -p wa -k hosts ; -a always,exit -F arch=b64 -S sethostname,setdomainname -k hosts' ;;
    esac
}

build_findings() {
    step STEP 'Evaluation'
    local row
    # ---- collection
    [ $IS_ROOT -eq 0 ] && add_finding High Collection 'Script was not run as root - results are incomplete' 'Auth / audit logs, auditctl, /etc/shadow, sudoers and deleted-file checks need root.' '' 'Re-run with sudo.'
    have utmpdump || add_finding Low Collection 'utmpdump not available - wtmp / btmp could not be parsed' 'Logon history comes only from the auth log.' '' 'Install util-linux (or sysvinit-tools on old RHEL), or analyse wtmp offline.'

    # ---- tampering: auditd
    if [ $AUD_INSTALLED -eq 0 ]; then
        add_finding High Visibility 'auditd is not installed' 'Without auditd there is no record of command execution, file changes or privilege use on this host (unless an EDR covers it).' '' 'Install auditd (audit / auditd package) and deploy a baseline rule set (e.g. Neo23x0 / Florian Roth auditd rules or the CIS rules).' 'T1562.012'
    else
        if [ $AUD_RUNNING -eq 0 ]; then
            local sev=High; [ "$AUD_SVC_EN" = enabled ] && sev=Critical
            add_finding "$sev" Tampering 'auditd is installed but not running' "Service state: $AUD_SVC / $AUD_SVC_EN. A stopped audit daemon is a classic defense evasion step." '' 'Start auditd, then look for who stopped it (DAEMON_END in audit.log, systemctl / service commands in histories and sudo logs).' 'T1562.012'
        fi
        [ "$AUD_ENABLED" = 0 ] && add_finding Critical Tampering 'Kernel auditing is disabled (auditctl enabled=0)' 'auditd is running but the kernel does not generate audit events.' '' 'auditctl -e 1 (and -e 2 to lock); search for "auditctl -e 0" in histories / audit.log.' 'T1562.012'
        [ "${KERNEL_AUDIT_OFF:-0}" -eq 1 ] && add_finding Critical Tampering 'Kernel booted with audit=0' 'Auditing is switched off on the kernel command line; auditd cannot record anything.' "$(cat /proc/cmdline 2>/dev/null)" 'Remove audit=0 from the boot loader configuration and check when it was added.' 'T1562.012'
        if [ $AUD_READ -eq 1 ] && [ "$AUD_RULES_LOADED" -eq 0 ] && [ "$AUD_RULES_PERSIST" -gt 0 ]; then
            add_finding Critical Tampering 'Audit rules exist on disk but none are loaded' "$AUD_RULES_PERSIST persistent rule(s) in /etc/audit, 0 loaded in the kernel - typical after \"auditctl -D\"." '' 'Reload with augenrules --load and search for auditctl -D in histories and audit CONFIG_CHANGE records.' 'T1562.012'
        else
            local nl; nl=$(awk -F'\t' '$4=="Not loaded" { printf "%s; ", $2 }' "$F_AR")
            [ -n "$nl" ] && add_finding High Tampering 'Some audit rules on disk are not loaded' 'The running rule set is weaker than the persistent configuration - rules were removed at runtime or the rule files were changed without reload.' "$nl" 'Compare auditctl -l with /etc/audit/rules.d; reload with augenrules --load.' 'T1562.012'
        fi
        [ -n "$AUD_LOST" ] && [ "$AUD_LOST" -gt 0 ] 2>/dev/null && add_finding High Tampering "auditd reports $AUD_LOST lost event(s)" "The kernel dropped audit records (backlog_limit ${AUD_BACKLOG:-?} too small, or the daemon was overwhelmed / stopped)." '' 'Increase -b (backlog_limit, e.g. 8192) and check for flooding.' 'T1562.012'
        [ "$(audv write_logs 2>/dev/null | tr A-Z a-z)" = no ] && add_finding Critical Tampering 'auditd.conf write_logs = no' 'auditd does not write audit.log at all.' '' 'Set write_logs = yes and find out who changed auditd.conf.' 'T1562.012'
        case "$(audv disk_full_action 2>/dev/null | tr a-z A-Z)" in IGNORE|SUSPEND) add_finding Medium Retention 'auditd stops logging when the disk is full' "disk_full_action = $(audv disk_full_action) - an attacker can fill the disk to blind auditing." '' 'Use SYSLOG/SINGLE/HALT according to policy and monitor /var/log/audit space.' 'T1562.012' ;; esac
        [ $AUD_IMMUTABLE -eq 0 ] && [ "$AUD_RULES_LOADED" -gt 0 ] && add_finding Low Hardening 'Audit rules are not locked (-e 2)' 'Without -e 2 anyone with root can change or delete rules at runtime without a reboot.' '' 'Add -e 2 as the last line of the rules (rule changes then need a reboot).' 'T1562.012'
    fi
    # ---- tampering: syslog / journal
    if [ $SYSLOGD_RUN -eq 0 ] && [ -n "$SYSLOGD" ]; then
        add_finding High Tampering "Syslog daemon ($SYSLOGD) is installed but not running" 'Text logs such as auth.log / secure are not written.' '' 'Start the service and check when and by whom it was stopped.' 'T1562.006'
    fi
    if [ "$JOURNAL_STORAGE" = none ]; then add_finding Critical Tampering 'journald Storage=none' 'The journal stores nothing.' '' 'Set Storage=persistent in journald.conf.' 'T1562.006'
    elif [ $SYSTEMD -eq 1 ] && [ $JOURNAL_PERSIST -eq 0 ]; then add_finding Medium Retention 'systemd journal is volatile' "Storage=$JOURNAL_STORAGE and no /var/log/journal - the journal is lost at every reboot." '' 'mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal, or Storage=persistent.' ''; fi
    # ---- log files
    while IFS=$'\037' read -r kind name path status nf bytes oldest newest lines rate span mode cap why note; do
        case "$kind" in
            auth)
                if [ "$status" = Missing ] && [ $SYSLOGD_RUN -eq 1 ]; then add_finding High Tampering "Authentication log $path is missing" 'The syslog daemon runs but the auth log does not exist - it may have been deleted.' '' 'Check the rsyslog destination for authpriv and the parent directory timestamps.' 'T1070.002'
                elif [ "$status" = Empty ] && [ $SYSLOGD_RUN -eq 1 ]; then add_finding High Tampering "Authentication log $path is empty" 'An empty auth log on a running system with rotated copies missing usually means it was truncated.' '' 'Check for truncate / > redirection in histories and EXECVE records.' 'T1070.002'; fi ;;
            wtmp) if [ "$status" = Missing ] || [ "$status" = Empty ]; then add_finding High Tampering "Login record file $path is $status" 'wtmp holds every logon and reboot; an empty or missing file usually means it was cleared.' '' 'Recover from backups / snapshots; rely on auth log and journal for logon history.' 'T1070.003'; fi ;;
            btmp) [ "$status" = Missing ] && add_finding Low Retention 'btmp (failed logins) does not exist' 'Failed logons are not recorded in btmp.' '' 'touch /var/log/btmp && chmod 600 /var/log/btmp' '' ;;
        esac
        [ -n "$note" ] && [ "$status" = OK ] && case "$kind" in auth|syslog|audit|auth2) add_finding High Tampering "$name: $note" "$path is empty although rotated copies exist and it was not written for a day." '' 'Check whether the file was truncated (truncate, : >, echo > ...).' 'T1070.002' ;; esac
    done < <(tr '\t' '\037' < "$F_LOGS")
    [ -n "$DELETED_OPEN" ] && add_finding Critical Tampering 'Log files were deleted while still open' 'A process still holds a deleted log file - the file was removed from disk (typical for log wiping). The content can be recovered from /proc/<pid>/fd/<n>.' "$(printf '%s' "$DELETED_OPEN" | head -5 | tr '\n' ';')" 'Copy the data now: cp /proc/<pid>/fd/<n> /mnt/usb/recovered.log - before the process is restarted.' 'T1070.002'
    [ -n "$LOG_IMMUTABLE" ] && add_finding High Tampering 'Log files carry the immutable attribute' 'chattr +i prevents the logging daemon from writing - new events are lost silently.' "$LOG_IMMUTABLE" 'lsattr / chattr -i the files and find out who set it.' 'T1562.006'
    [ -n "$PRELOAD" ] && add_finding Critical Tampering '/etc/ld.so.preload is in use' 'Libraries listed here are loaded into every process - the most common way userland rootkits hide files, processes and log entries.' "$PRELOAD" 'Verify the library (package owner, hash). A rootkit can hide data from this script - analyse the disk offline.' 'T1574.006'
    [ -n "$HIST_OFF_FILES" ] && add_finding High Tampering 'Shell history is disabled in a profile file' 'HISTFILE=/dev/null, unset HISTFILE, HISTSIZE=0 or set +o history removes the command trail.' "$HIST_OFF_FILES" 'Remove the setting and check when the file was modified.' 'T1070.003'
    [ -n "$HIST_NULL" ] && add_finding High Tampering 'Shell history file is linked to /dev/null' 'Commands of this user are never saved.' "$HIST_NULL" 'Remove the symlink; check the file change time.' 'T1070.003'
    # ---- tampering events
    local nc nl np ns
    nc=$(awk -F'\t' '$4=="clear"' "$F_EV" | grep -c .); np=$(awk -F'\t' '$4=="policy" && ($2=="Critical"||$2=="High")' "$F_EV" | grep -c .)
    nl=$(awk -F'\t' '$4=="lost"' "$F_EV" | grep -c .); ns=$(awk -F'\t' '$4=="svc"' "$F_EV" | grep -c .)
    [ "$np" -gt 0 ] && add_finding Critical Tampering "$np audit rule removal / disable event(s)" 'Audit rules were removed or auditing was disabled at runtime.' "$(awk -F'\t' '$4=="policy" && ($2=="Critical"||$2=="High") { print $1 "|" $5 "|" $6 }' "$F_EV" | head -5 | awkx -F'|' '{ printf "%s %s %s; ", fmt($1), $2, $3 }')" 'Identify the auid (login user) in the records and review that session.' 'T1562.012'
    [ "$nl" -gt 0 ] && add_finding High Tampering "$nl audit event loss message(s)" 'The kernel reported a backlog overflow or lost audit records.' '' 'Increase backlog_limit; check whether the loss coincides with suspicious activity (flooding).' 'T1562.012'
    [ "$ns" -gt 0 ] && add_finding Medium Tampering "$ns logging service stop(s) outside a system shutdown" 'auditd, rsyslog or journald stopped while the system kept running.' "$(awk -F'\t' '$4=="svc" { print $1 "|" $5 }' "$F_EV" | sort -n | tail -5 | awkx -F'|' '{ printf "%s %s; ", fmt($1), $2 }')" 'Match the times against sudo / su logs and shell histories.' 'T1562.006'
    # ---- visibility
    local mk mo
    mk=$(awk -F'\t' '$8==1 && $4!="OK" && $4!="Persistent only" { printf "%s %s; ", $1, $2 }' "$F_AR")
    mo=$(awk -F'\t' '$8==0 && $4!="OK" && $4!="Persistent only" { printf "%s %s; ", $1, $2 }' "$F_AR")
    if [ $AUD_INSTALLED -eq 1 ] && [ -n "$mk" ]; then
        local rec=''; local id; for id in $(awk -F'\t' '$8==1 && $4!="OK" && $4!="Persistent only" { print $1 }' "$F_AR" | head -6); do rec="$rec$(AUDIT_RULE_SAMPLE "$id") ; "; done
        add_finding High Visibility "$(echo "$mk" | grep -o 'A[0-9][0-9]' | wc -l) key audit rule(s) missing" 'These rules cover the core Linux attacker techniques (execution, persistence, log tampering).' "$mk" "Add to /etc/audit/rules.d/ir.rules and run augenrules --load: $rec" ''
    fi
    [ $AUD_INSTALLED -eq 1 ] && [ -n "$mo" ] && add_finding Low Visibility "$(echo "$mo" | grep -o 'A[0-9][0-9]' | wc -l) optional audit rule(s) missing" 'Additional CIS / ASD recommended rules.' "$mo" 'See the audit rules table for example rules.' ''
    if ! awk -F'\t' '$1=="A01" && ($4=="OK"||$4=="Persistent only") { f=1 } END { exit !f }' "$F_AR" && [ "$EDR_COUNT" -eq 0 ]; then
        add_finding High Visibility 'No process execution logging' 'Neither an auditd execve rule nor an EDR agent records executed commands - attacker activity on this host cannot be reconstructed.' '' 'Add the execve audit rule (A01) or deploy the EDR agent.' 'T1059.004'
    fi
    [ "$EDR_COUNT" -eq 0 ] && add_finding Medium Visibility 'No EDR agent running' 'No endpoint detection agent (Cortex XDR, CrowdStrike, Defender, SentinelOne ...) was found running.' "$(cut -f2,3 "$F_AGENT" | tr '\t\n' ' ;')" 'Verify the EDR deployment for this server.' ''
    [ -n "$SSHD_LOGLEVEL" ] && case "$(echo "$SSHD_LOGLEVEL" | tr a-z A-Z)" in VERBOSE|DEBUG*) ;; *) add_finding Low Visibility "sshd LogLevel is $(echo "$SSHD_LOGLEVEL" | tr a-z A-Z)" 'With INFO the key fingerprint used for a logon is not logged - SSH key logons cannot be attributed to a specific key.' '' 'Set LogLevel VERBOSE in sshd_config.' 'T1021.004' ;; esac
    [ $HIST_TIME -eq 0 ] && add_finding Low Visibility 'Shell history has no timestamps' 'Without HISTTIMEFORMAT commands in .bash_history cannot be placed on a timeline.' '' "echo 'export HISTTIMEFORMAT=\"%F %T \"' > /etc/profile.d/histtime.sh" ''
    # ---- retention
    local arow; arow=$(log_row auth)
    if [ -n "$arow" ]; then
        local ao an; ao=$(printf '%s' "$arow" | cut -f7); an=$(printf '%s' "$arow" | cut -f3)
        if [ -n "$ao" ]; then
            local hist=$(( NOW - ao ))
            if [ -n "$SUSPECT" ] && [ "$ao" -gt "$SUSPECT" ]; then add_finding High Retention "Authentication log does not reach back to the suspected start" "Oldest entry $(fmt_epoch "$ao"), suspected start $(fmt_epoch "$SUSPECT")." "$an" 'Recover older logs from backups / SIEM; increase logrotate rotate count.' ''
            elif [ $hist -lt 604800 ]; then add_finding Medium Retention "Authentication log covers only $(( hist / 3600 )) hours" "Oldest entry $(fmt_epoch "$ao")." "$an" 'Keep at least 90 days locally (logrotate rotate 13 weekly / 90 daily) or rely on the SIEM.' ''; fi
        fi
    fi
    arow=$(log_row audit)
    if [ -n "$arow" ]; then
        local acap; acap=$(printf '%s' "$arow" | cut -f13)
        [ -n "$acap" ] && awk -v c="$acap" 'BEGIN{ exit !(c<168) }' && add_finding Medium Retention "auditd keeps only about $(awk -v c="$acap" 'BEGIN{ printf "%.0f", c }') hours of events" "num_logs x max_log_file at the current event rate." "$(printf '%s' "$arow" | cut -f12)" 'Increase num_logs / max_log_file, or forward audit.log to the SIEM.' ''
    fi
    # ---- SIEM
    if [ $SPLUNK -eq 0 ] && [ -z "$(echo $SYSLOG_FWD)" ] && [ "$FWD_COUNT" -eq 0 ] && [ $AUDISP_REMOTE -eq 0 ]; then
        add_finding High SIEM 'No log forwarding found' 'No Splunk forwarder, syslog forwarding rule or log shipper - all evidence exists only on this (possibly compromised) host.' '' 'Install the Splunk Universal Forwarder with inputs for auth / syslog / audit logs.' ''
    fi
    if [ $SPLUNK -eq 1 ]; then
        [ $SPLUNK_RUN -eq 0 ] && add_finding High Tampering 'Splunk forwarder is installed but not running' "$SPLUNK_HOME - nothing is forwarded." '' 'Start splunkd and check when it stopped (splunkd.log, systemctl status).' 'T1562.001'
        local k
        for k in auth audit syslog; do
            local r p st; r=$(log_row "$k"); [ -z "$r" ] && continue; p=$(printf '%s' "$r" | cut -f3)
            st=$(awk -F'\t' -v p="$p" '$1==p { print $2 "\t" $3; exit }' "$F_SPF")
            case "$(printf '%s' "$st" | cut -f1)" in
                NotCollected|Filtered) add_finding "$( [ "$k" = syslog ] && echo Medium || echo High )" SIEM "$p is not forwarded to Splunk" "$(printf '%s' "$st" | cut -f2)" '' "Add [monitor://$p] with the right index / sourcetype (linux_secure, linux_audit, syslog)." '' ;;
            esac
        done
        [ "${SPLUNK_ERR:-0}" -gt 0 ] && add_finding Medium SIEM "Splunk output errors in splunkd.log ($SPLUNK_ERR in the last 20,000 lines)" 'Forwarding to the indexers is failing or unstable - events may be queued or lost.' "$(head -3 "$RAW/splunkd_errors_tail.txt" 2>/dev/null | tr '\n' ' ' | cut -c1-300)" 'Check connectivity to the indexers and outputs.conf.' ''
    fi
    # ---- deep scan
    if [ $DEEP -eq 1 ]; then
        local sg; sg=$(awk -F'\t' '$2=="serial" { n+=$5; c++ } END { if (c) print c " gap(s), " n " record(s)" }' "$F_GAPS")
        [ -n "$sg" ] && add_finding High Tampering "Audit record serial numbers have gaps ($sg)" 'auditd serial numbers increase by one per event. Gaps mean records were removed from audit.log, dropped by the kernel (backlog) or suppressed.' "$(awk -F'\t' '$2=="serial"' "$F_GAPS" | head -5 | awkx -F'\t' '{ printf "%s: %s missing; ", fmt($3), $5 }')" 'Correlate with lost-event messages; if there is no loss, treat as deliberate deletion.' 'T1070.002'
        local ug; ug=$(awk -F'\t' '$2=="time"' "$F_GAPS" | tr '\t' '\037' | while IFS=$'\037' read -r l ty a b m; do
            awk -F'\t' -v a="$a" -v b="$b" '$1>=a && $1<=b+300 { f=1 } END { exit f }' "$F_BOOT" && printf '%s: %s -> %s (%s min); ' "$l" "$(fmt_epoch "$a")" "$(fmt_epoch "$b")" "$m"; done)
        [ -n "$ug" ] && add_finding Medium Tampering 'Periods without events that are not explained by a reboot' "Silences longer than $GAP_MIN minutes in busy logs." "$(printf '%s' "$ug" | cut -c1-600)" 'Compare with the other logs and the SIEM for the same period.' 'T1070.002'
        local bk; bk=$(awk -F'\t' '$2=="backwards" && $1!="wtmp"' "$F_GAPS" | grep -c .)
        [ "$bk" -gt 0 ] && add_finding Medium Tampering "$bk backwards time jump(s) inside log files" 'Lines with older timestamps after newer ones - clock changes or edited / spliced log files.' '' 'Check for time-change events at the same moments.' 'T1070.006'
        [ "${WTMP_BAD:-0}" -gt 0 ] || [ "${WTMP_ORDER:-0}" -gt 0 ] && add_finding High Tampering 'wtmp contains zeroed or out-of-order records' "$WTMP_BAD zeroed / empty record(s), $WTMP_ORDER backwards jump(s) - typical for utmp log cleaners." '' 'Treat logon history as unreliable; compare with auth log and SIEM.' 'T1070.003'
        [ "${JVERIFY:-0}" -gt 0 ] && add_finding Medium Tampering 'journalctl --verify reports problems' 'Corrupted journal files can come from crashes or from manipulation.' "$(head -3 "$RAW/journal_verify.txt" | tr '\n' ' ')" 'Review raw/journal_verify.txt.' 'T1070.002'
        local cm; cm=$(grep -c . "$F_CMD")
        [ "$cm" -gt 0 ] && add_finding Critical Tampering "$cm anti-logging command(s) found" 'Commands that clear logs, disable auditing or hide history were executed.' "$(cut -f3,4 "$F_CMD" | head -5 | tr '\t\n' ': ' | cut -c1-500)" 'Review the deep scan section; identify the user and session.' 'T1070'
    fi
}

access_findings() {
    local x
    x=$(awk -F'\t' '$2==0 && $1!="root" { printf "%s ", $1 }' "$F_USERS")
    [ -n "$x" ] && add_finding Critical Access 'Additional account(s) with UID 0' 'Any account with UID 0 is root. Attackers add such accounts as a backdoor.' "$x" 'Remove or re-number the account after confirming it is not authorised.' 'T1136.001'
    x=$(awk -F'\t' '$7=="EMPTY" && $6==1 { printf "%s ", $1 }' "$F_USERS")
    [ -n "$x" ] && add_finding Critical Access 'Account(s) with an empty password and a login shell' 'Anyone can log on (locally, or via SSH if PermitEmptyPasswords is yes).' "$x" 'passwd -l the account(s).' 'T1078.003'
    local np; np=$(awk -F'\t' '$1 !~ /^%/' "$F_PRIV" | cut -f1 | sort -u | grep -c .)
    local sev=Info; [ "$np" -gt 10 ] && sev=Medium
    add_finding "$sev" Access "$np account(s) with root or sudo rights" 'UID 0, members of sudo / wheel / admin, and sudoers entries.' "$(awk -F'\t' '$1 !~ /^%/ { print $1 }' "$F_PRIV" | sort -u | tr '\n' ' ')" 'Remove rights that are not needed; prefer named admin accounts.' 'T1078'
    x=$(grep -E 'NOPASSWD' "$F_PRIV" | grep 'full root' | cut -f1 | sort -u | tr '\n' ' ')
    [ -n "$x" ] && add_finding Medium Access 'Passwordless full root via sudo (NOPASSWD)' 'A stolen session or SSH key of these accounts gives root without a password.' "$x" 'Require a password for interactive admin accounts.' 'T1548.003'
    x=$(awk -F: '$1=="docker" || $1=="lxd" || $1=="libvirt" || $1=="disk" { if ($4!="") printf "%s: %s; ", $1, $4 }' /etc/group 2>/dev/null)
    [ -n "$x" ] && add_finding Medium Access 'Members of root-equivalent groups (docker / lxd / libvirt / disk)' 'These groups allow trivial escalation to root.' "$x" 'Treat these members as administrators.' 'T1611'
    case "$SSHD_ROOT" in yes) add_finding Medium Access 'SSH allows root logon with a password (PermitRootLogin yes)' '' '' 'Set PermitRootLogin no (or prohibit-password).' 'T1021.004' ;; esac
    case "$SSHD_EMPTY" in yes) add_finding High Access 'sshd PermitEmptyPasswords yes' '' '' 'Set PermitEmptyPasswords no.' 'T1078' ;; esac
    if [ -s "$F_KEYS" ]; then
        x=$(awk -F'\t' '$1=="root" { printf "%s (%s key(s)); ", $2, $3 }' "$F_KEYS")
        [ -n "$x" ] && add_finding Info Access 'root has SSH authorized_keys' 'Every listed key gives direct root access.' "$x" 'Verify every key owner; prefer named accounts plus sudo.' 'T1098.004'
        if [ -n "$SUSPECT" ]; then
            x=$(awk -F'\t' -v s="$SUSPECT" '$4>=s { printf "%s ", $2 }' "$F_KEYS")
            [ -n "$x" ] && add_finding High Access 'authorized_keys modified after the suspected start' 'Adding an SSH key is the most common Linux persistence technique.' "$x" 'Compare the keys with known admin keys; remove unknown keys.' 'T1098.004'
        else
            x=$(awk -F'\t' -v n="$NOW" '$4>=n-2592000 { printf "%s ", $2 }' "$F_KEYS")
            [ -n "$x" ] && add_finding Low Access 'authorized_keys modified in the last 30 days' '' "$x" 'Confirm the change with the account owner.' 'T1098.004'
        fi
    fi
    x=$(awkx -F'\t' '{ n=split($5,a,"; "); for (i=1;i<=n;i++) { split(a[i],b,"="); if (ispub(b[1])) printf "%s from %s; ", $1, b[1] } }' "$F_LOGON")
    [ -n "$x" ] && add_finding High Access 'Logons from public IP addresses' 'SSH exposed to the Internet is a top initial access vector.' "$(printf '%s' "$x" | cut -c1-600)" 'Restrict SSH to the management network / bastion; check these sources against threat intelligence.' 'T1133'
    local bf; bf=$(awk -F'\t' '$2>=20' "$F_FAIL" | grep -c .)
    if [ "$bf" -gt 0 ]; then
        sev=Medium; awkx -F'\t' '$2>=20 && ispub($1) { f=1 } END { exit !f }' "$F_FAIL" && sev=High
        add_finding "$sev" Access "$bf source(s) with 20 or more failed logons" 'Password guessing / brute force.' "$(awk -F'\t' '$2>=20 { printf "%s: %s failures, %s account(s); ", $1, $2, $3 }' "$F_FAIL" | cut -c1-500)" 'Check whether any of these sources later logged on successfully; use fail2ban / firewall.' 'T1110'
        x=$(awk -F'\t' 'NR==FNR { if ($2>=20) bad[$1]=1; next } { n=split($5,a,"; "); for (i=1;i<=n;i++) { split(a[i],b,"="); if (b[1] in bad) printf "%s from %s; ", $1, b[1] } }' "$F_FAIL" "$F_LOGON")
        [ -n "$x" ] && add_finding Critical Access 'Successful logon from a brute-force source' 'A source with 20+ failed logons also logged on successfully - likely a guessed password.' "$x" 'Reset the password, review the session, treat the account as compromised.' 'T1110'
    fi
    x=$(awk -F'\t' '$3=="denied"' "$F_SUDO" | cut -f2 | sort | uniq -c | awk '{ printf "%s (%s); ", $2, $1 }')
    [ -n "$x" ] && add_finding Medium Access 'Denied sudo attempts' 'Wrong passwords or commands not allowed - can indicate privilege escalation attempts.' "$x" 'Review the attempts in the auth log.' 'T1548.003'
    local cg; cg=$(awk -F'\t' '($2=="added to group" && $4 ~ /^(sudo|wheel|admin|root|docker|adm|lxd|disk|shadow)$/) || $2=="account created"' "$F_CHG")
    if [ -n "$cg" ]; then
        sev=High; [ -n "$SUSPECT" ] && printf '%s\n' "$cg" | awk -F'\t' -v s="$SUSPECT" '$1>=s { f=1 } END { exit !f }' && sev=Critical
        add_finding "$sev" Access "$(printf '%s\n' "$cg" | grep -c .) account creation / privileged group change(s) in the logs" 'New accounts and new members of admin groups are common persistence steps.' "$(printf '%s\n' "$cg" | sort -n | tail -10 | awkx -F'\t' '{ printf "%s %s %s %s; ", fmt($1), $2, $3, $4 }')" 'Confirm each change with its owner and change ticket.' 'T1136.001'
    fi
    if [ -n "$SUSPECT" ]; then
        x=$(awk -F'\t' -v s="$SUSPECT" '$3>=s { printf "%s (first %s); ", $1, $3 }' "$F_LOGON" | awkx '{ print }')
        local oldest_logon; oldest_logon=$(awk -F'\t' 'NR==1 || $3<m { m=$3 } END { print m }' "$F_LOGON")
        if [ -n "$x" ] && [ -n "$oldest_logon" ] && [ "$oldest_logon" -lt "$SUSPECT" ]; then
            add_finding High Access 'Account(s) that logged on for the first time after the suspected start' 'The logon history reaches back further, but these accounts appear only after the suspected start.' "$(awk -F'\t' -v s="$SUSPECT" '$3>=s { print $1 }' "$F_LOGON" | tr '\n' ' ')" 'Treat these accounts as compromised until explained.' 'T1078'
        fi
    fi
    local nl; nl=$(grep -c . "$F_LOGON")
    [ "$nl" -gt 0 ] && add_finding Info Access "$nl account(s) with logon evidence" 'From wtmp and the auth log (Accepted ...). See the Privileged access section.' "$(head -10 "$F_LOGON" | awkx -F'\t' '{ printf "%s (last %s); ", $1, fmt($4) }')" 'Confirm that every interactive admin logon is expected.' 'T1078'
}

compute_score() {
    # integrity
    local t c
    read -r t c < <(awk -F'\t' 'BEGIN { p["Critical"]=15; p["High"]=7; p["Medium"]=3; p["Low"]=1; s=25 } $2=="Tampering" { s-=p[$1]; if ($1=="Critical") c++ } END { if (s<0) s=0; print s, c+0 }' "$F_FIND")
    CRIT_TAMPER=$c
    printf 'Integrity (no tampering)\t%s\t25\t%s tampering finding(s), %s critical\n' "$t" "$(awk -F'\t' '$2=="Tampering"' "$F_FIND" | grep -c .)" "$c" >> "$F_AREA"
    # audit policy
    local a=0 note='auditd not running'
    if [ $AUD_RUNNING -eq 1 ] && [ "$AUD_ENABLED" != 0 ]; then
        read -r a note < <(awk -F'\t' '{ w=($8==1)?2:1; tot+=w; if ($4=="OK"||$4=="Persistent only") ok+=w } END { printf "%.1f %d/%d weighted baseline rules in place\n", (tot?25*ok/tot:0), ok, tot }' "$F_AR")
    elif [ $AUD_INSTALLED -eq 0 ]; then note='auditd not installed'; fi
    printf 'auditd rules vs. baseline\t%s\t25\t%s\n' "$a" "$note" >> "$F_AREA"
    # extended visibility
    local v=0
    awk -F'\t' '$1=="A01" && ($4=="OK"||$4=="Persistent only") { f=1 } END { exit !f }' "$F_AR" && v=$((v+5))
    [ "$EDR_COUNT" -gt 0 ] && v=$((v+4))
    case "$(echo "$SSHD_LOGLEVEL" | tr a-z A-Z)" in VERBOSE|DEBUG*) v=$((v+2)) ;; esac
    [ $HIST_TIME -eq 1 ] && v=$((v+2))
    { [ $JOURNAL_PERSIST -eq 1 ] || [ $SYSTEMD -eq 0 ]; } && v=$((v+2))
    printf 'Extended visibility (execve, EDR, sshd, history)\t%s\t15\texecve audit 5, EDR 4, sshd VERBOSE 2, history timestamps 2, persistent journal 2\n' "$v" >> "$F_AREA"
    # SIEM
    local s=0 sn='no log forwarding'
    if [ $SPLUNK -eq 1 ]; then
        s=$(awk -F'\t' '$5=="Covered"||$5=="Partial" { n++; if ($7=="Forwarded") g+=1; else if ($7=="Partial") g+=0.5; else if ($7=="EDR"||$7=="n/a") g+=1 } END { printf "%.1f", (n?16*g/n:0) }' "$F_UC")
        [ $SPLUNK_RUN -eq 1 ] && s=$(awk -v s="$s" 'BEGIN{ print s+2 }') || s=0
        [ $SPLUNK_RUN -eq 1 ] && [ "${SPLUNK_ERR:-0}" -eq 0 ] && s=$(awk -v s="$s" 'BEGIN{ print s+2 }')
        sn="Splunk UF ${SPLUNK_VER:-?}: $(awk -F'\t' '$5=="Covered"||$5=="Partial" { n++; if ($7=="Forwarded"||$7=="EDR"||$7=="n/a") g++ } END { printf "%.0f", (n?100*g/n:0) }' "$F_UC")% of locally logged use cases reach the SIEM"
    elif [ -n "$(echo $SYSLOG_FWD)" ] || [ "$FWD_COUNT" -gt 0 ] || [ $AUDISP_REMOTE -eq 1 ]; then s=8; sn='forwarding present (syslog / agent) but coverage not verifiable'; fi
    printf 'SIEM forwarding\t%s\t20\t%s\n' "$s" "$sn" >> "$F_AREA"
    # local coverage
    local l=0 ln='auth log not readable' r ao
    r=$(log_row auth)
    if [ -n "$r" ]; then ao=$(printf '%s' "$r" | cut -f7)
        if [ -n "$ao" ]; then local hh=$(( (NOW - ao) / 3600 ))
            if [ -n "$SUSPECT" ]; then [ "$ao" -le "$SUSPECT" ] && l=$(awk -v l="$l" 'BEGIN{print l+6}')
            elif [ $hh -ge 2160 ]; then l=6; elif [ $hh -ge 720 ]; then l=4.5; elif [ $hh -ge 168 ]; then l=3; elif [ $hh -ge 24 ]; then l=1.5; fi
            ln="auth log history $(awk -v h="$hh" 'BEGIN{ if (h<48) printf "%d h", h; else printf "%.0f days", h/24 }')"
        fi
    elif [ $SYSTEMD -eq 1 ]; then r=$(log_row journal); ao=$(printf '%s' "$r" | cut -f7)
        [ -n "$ao" ] && { local hh=$(( (NOW - ao) / 3600 )); [ $hh -ge 720 ] && l=4.5 || { [ $hh -ge 168 ] && l=3 || l=1.5; }; ln="journal history $(( hh / 24 )) days (no auth log file)"; }
    fi
    awk -F'\t' '$1=="audit" && $4=="OK" && $11>=604800 { f=1 } END { exit !f }' "$F_LOGS" && l=$(awk -v l="$l" 'BEGIN{print l+3}')
    local bad; bad=$(awk -F'\t' '($1=="auth"||$1=="syslog"||$1=="wtmp") && $4!="OK"' "$F_LOGS" | grep -c .)
    { [ "$bad" -eq 0 ] && { [ $SYSLOGD_RUN -eq 1 ] || [ $SYSTEMD -eq 1 ]; }; } && l=$(awk -v l="$l" 'BEGIN{print l+3}')
    { [ $JOURNAL_PERSIST -eq 1 ] || awk -F'\t' '$1=="auth" && $13>=2160 { f=1 } END { exit !f }' "$F_LOGS"; } && l=$(awk -v l="$l" 'BEGIN{print l+3}')
    printf 'Local log coverage and health\t%s\t15\t%s\n' "$l" "$ln" >> "$F_AREA"
    SCORE=$(awk -F'\t' '{ s+=$2 } END { printf "%.0f", s }' "$F_AREA"); SCORE_CAPPED=0
    [ "$CRIT_TAMPER" -gt 0 ] && [ "$SCORE" -gt 59 ] && { SCORE=59; SCORE_CAPPED=1; }
    GRADE=F; LABEL=Insufficient
    if [ "$SCORE" -ge 90 ]; then GRADE=A; LABEL=Good; elif [ "$SCORE" -ge 75 ]; then GRADE=B; LABEL=Adequate; elif [ "$SCORE" -ge 60 ]; then GRADE=C; LABEL=Limited; elif [ "$SCORE" -ge 40 ]; then GRADE=D; LABEL=Poor; fi
}

verdict() {
    local tc gaps; tc=$(awk -F'\t' '$2=="Tampering" && ($1=="Critical"||$1=="High")' "$F_FIND" | grep -c .)
    gaps=$(awk -F'\t' '$10==1 && $5=="Gap"' "$F_UC" | grep -c .)
    local v=''
    if [ "$tc" -gt 0 ]; then v="Logging on this host shows $tc critical / high tampering indicator(s) - treat local logs as incomplete and preserve them now. "
    else v='No critical tampering indicators were found in the available data. '; fi
    if [ "$gaps" -gt 0 ]; then v="${v}$gaps key detection use case(s) have no evidence source. "; fi
    case "$GRADE" in A|B) v="${v}Overall the logging supports an investigation well." ;; C) v="${v}An investigation is possible but with blind spots." ;; *) v="${v}Logging is not sufficient for a reliable investigation of this host." ;; esac
    printf '%s' "$v"
}

# =====================================================================================================
#  10. Report
# =====================================================================================================
REPORT_CSS=$(cat <<'CSSEOF'
:root{--bg:#f3f5f8;--card:#ffffff;--text:#1b2430;--muted:#5f6b7a;--border:#dde3ea;--head:#0f2742;--head-text:#ffffff;--accent:#1d63d8;
--crit:#9f1239;--high:#dc2626;--med:#d97706;--low:#2563eb;--info:#64748b;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--off:#a3acb9;--na:#94a3b8;
--grid:#e6eaf0;--row:#f7f9fb}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#9aa7b4;--border:#2d3540;--head:#0b1f36;--row:#1b222c;--grid:#2a323d;--off:#5b6573;--accent:#58a6ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
.wrap{max-width:1260px;margin:0 auto;padding:0 18px}
header.top{background:var(--head);color:var(--head-text);padding:22px 0 18px}
header .brand{font-size:12px;letter-spacing:.12em;text-transform:uppercase;opacity:.75}
header h1{margin:4px 0 6px;font-size:26px}
header .meta{font-size:13px;opacity:.88}
nav.toc{display:flex;flex-wrap:wrap;gap:6px;margin:16px 0}
nav.toc a{color:var(--accent);background:var(--card);border:1px solid var(--border);border-radius:16px;padding:3px 12px;text-decoration:none;font-size:13px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px 20px;margin:0 0 18px}
.card h2{margin:0 0 4px;font-size:19px}
.card h3{margin:16px 0 6px;font-size:15px}
.card .sub{color:var(--muted);margin:0 0 14px;font-size:13px}
.grid-sum{display:grid;grid-template-columns:210px 1fr 1fr;gap:22px;align-items:start}
@media (max-width:960px){.grid-sum{grid-template-columns:1fr}}
.gauge .track{stroke:var(--grid)} .gauge text{fill:var(--text)}
.area{margin:0 0 11px} .area .lbl{display:flex;justify-content:space-between;font-size:13px;gap:8px} .area .note{font-size:11px;color:var(--muted)}
.bar{height:8px;background:var(--grid);border-radius:4px;overflow:hidden;margin-top:3px} .bar>span{display:block;height:100%;border-radius:4px}
.kpis{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.kpi{border:1px solid var(--border);border-radius:8px;padding:10px 12px;background:var(--row)}
.kpi .v{font-size:20px;font-weight:650} .kpi .k{font-size:12px;color:var(--muted)}
.verdict{border-left:4px solid var(--accent);background:var(--row);padding:10px 14px;margin:16px 0 0;border-radius:4px}
.tw{overflow-x:auto}
table.t{width:100%;border-collapse:collapse;font-size:13px}
table.t th{text-align:left;background:var(--row);color:var(--muted);font-weight:600;padding:7px 8px;border-bottom:1px solid var(--border);white-space:nowrap}
table.t td{padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
table.t tr:hover td{background:var(--row)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.b-Critical{background:var(--crit)} .b-High{background:var(--high)} .b-Medium{background:var(--med)} .b-Low{background:var(--low)} .b-Info{background:var(--info)}
.b-ok{background:var(--ok)} .b-warn{background:var(--warn)} .b-bad{background:var(--bad)} .b-na{background:var(--na)}
.muted{color:var(--muted)} .mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px;word-break:break-all} .small{font-size:12px} .nowrap{white-space:nowrap}
details{margin:8px 0} summary{cursor:pointer;font-weight:600;color:var(--accent)}
.tl{width:100%;height:auto;display:block}
.tl .lbl{fill:var(--text);font-size:12px} .tl .axis{fill:var(--muted);font-size:11px} .tl .gridl{stroke:var(--grid);stroke-width:1}
.tl .rowbg{fill:var(--row)} .tl .good{fill:var(--ok)} .tl .warn{fill:var(--warn)} .tl .bad{fill:var(--bad)} .tl .off{fill:var(--off)}
.tl .m-clear{fill:#dc2626;stroke:#fff;stroke-width:1.5} .tl .m-policy{fill:#f97316;stroke:#fff;stroke-width:1.5} .tl .m-svc{fill:#9333ea;stroke:#fff;stroke-width:1.5}
.tl .m-lost{fill:#facc15;stroke:#333;stroke-width:1} .tl .m-other{fill:#0ea5e9;stroke:#fff;stroke-width:1.5}
.tl .boot{stroke:var(--muted);stroke-dasharray:3 3} .tl .crash{stroke:#dc2626;stroke-dasharray:2 3} .tl .nowl{stroke:var(--text);stroke-width:1.5} .tl .suspect{stroke:#dc2626;stroke-width:2}
.tl .gap{fill:#dc2626;opacity:.35} .tl .hist{fill:var(--accent)} .tl .susp-t{fill:#dc2626;font-size:11px;font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted);margin:8px 0 2px}
.legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:5px;vertical-align:-2px}
.legend i.dot{border-radius:50%}
.filter{width:300px;max-width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--text);margin:0 0 8px}
.kv{display:grid;grid-template-columns:minmax(160px,280px) 1fr;gap:4px 14px;font-size:13px} .kv>div:nth-child(odd){color:var(--muted)}
.tag{display:inline-block;background:var(--row);border:1px solid var(--border);border-radius:4px;padding:0 6px;margin:1px 2px;font-size:12px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:16px 0 40px}
@media print{nav.toc,.filter{display:none} body{background:#fff} .card{break-inside:avoid-page;border-color:#ccc}}
.grade{font-weight:600;color:var(--muted)}
CSSEOF
)
REPORT_JS=$(cat <<'JSEOF'
document.querySelectorAll('input.filter').forEach(function(inp){inp.addEventListener('input',function(){var q=inp.value.toLowerCase();var t=document.getElementById(inp.getAttribute('data-table'));if(!t)return;t.querySelectorAll('tbody tr').forEach(function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?'':'none';});});});
JSEOF
)
RPTLIB='
function badge(t,c) { return "<span class=\"badge b-" c "\">" h(t) "</span>" }
function sbadge(s,   c,l) { c="na"
    if (s ~ /^(OK|Covered|Forwarded|ok)$/) c="ok"; else if (s ~ /^(Partial|Conditional|Persistent only|EDR|warn)$/) c="warn"
    else if (s ~ /^(Gap|Missing|Filtered|NotCollected|Not loaded|Inactive|Empty|Unreadable|bad)$/) c="bad"
    l=s; if (s=="NotCollected") l="Not collected"; else if (s=="None") l="No forwarder"; else if (s=="") l="n/a"
    else if (s=="ok") l="OK"; else if (s=="warn") l="Check"; else if (s=="bad") l="Gap"; else if (s=="na") l="-"
    return badge(l,c) }
function span(sec,  hr) { if (sec=="") return "n/a"; hr=sec/3600; if (hr<1) return sprintf("%d min", sec/60); if (hr<48) return sprintf("%.1f h", hr)
    if (hr<24*120) return sprintf("%.1f days", hr/24); return sprintf("%.1f months", hr/24/30.44) }
function wj(s) { gsub("\036"," || ",s); return s }
function size(b) { if (b=="") return ""; if (b>=1073741824) return sprintf("%.2f GB", b/1073741824); if (b>=1048576) return sprintf("%.1f MB", b/1048576); return sprintf("%.0f KB", b/1024) }
'
rawk() { local AO AP AF; awk_split "$@"; awk -v NOW="$NOW" -v TZOFF="$TZOFF" -v NOWY="$NOWY" -v SUSPECT="${SUSPECT:-0}" "${AO[@]}" "$AWKLIB$RPTLIB$AP" "${AF[@]}"; }
hesc() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

timeline_svg() {
    rawk -F'\t' '
        { fi=(FILENAME==ARGV[1])?1:((FILENAME==ARGV[2])?2:3) }
        fi==1 { if ($4=="Missing" || $7=="") next; n++; nm[n]=$2; o[n]=$7; nw[n]=$8; if (min==0 || $7<min) min=$7; next }
        fi==2 { if ($2=="boot") { nb++; bt[nb]=$1 }; next }
        fi==3 { if ($4=="boot" || $2=="Info") next; ne++; et[ne]=$1; ek[ne]=$4; ett[ne]=$5; ed[ne]=$6; next }
        END {
            if (n==0) { print "<p class=\"muted\">No timestamps available.</p>"; exit }
            st=min; if (SUSPECT>0 && SUSPECT-86400<st) st=SUSPECT-86400; if (st < NOW-400*86400) st=NOW-400*86400
            en=NOW+3600; W=1200; L=240; P=W-L-20; rh=26; H=40+(n+1)*rh+20
            printf "<svg class=\"tl\" viewBox=\"0 0 %d %d\" role=\"img\">", W, H
            for (i=0;i<=6;i++) { x=L+P*i/6; t=st+(en-st)*i/6; printf "<line class=\"gridl\" x1=\"%.1f\" y1=\"28\" x2=\"%.1f\" y2=\"%d\"/><text class=\"axis\" x=\"%.1f\" y=\"18\" text-anchor=\"middle\">%s</text>", x, x, H-14, x, substr(fmt(t),1,10) }
            y=36; printf "<rect class=\"rowbg\" x=\"0\" y=\"%d\" width=\"%d\" height=\"%d\"/><text class=\"lbl\" x=\"6\" y=\"%d\">Tampering events</text>", y, W, rh-4, y+16
            for (i=1;i<=ne;i++) { if (et[i]<st) continue; x=L+P*(et[i]-st)/(en-st); k=ek[i]; if (k!="clear" && k!="policy" && k!="svc" && k!="lost") k="other"
                printf "<circle class=\"m-%s\" cx=\"%.1f\" cy=\"%d\" r=\"5\"><title>%s %s&#10;%s</title></circle>", k, x, y+11, fmt(et[i]), h(ett[i]), h(ed[i]) }
            for (i=1;i<=n;i++) { y=36+i*rh
                if (i%2==0) printf "<rect class=\"rowbg\" x=\"0\" y=\"%d\" width=\"%d\" height=\"%d\"/>", y, W, rh-4
                c="bad"; if (SUSPECT>0) { if (o[i]<=SUSPECT) c="good" } else { hh=(NOW-o[i])/3600; if (hh>=168) c="good"; else if (hh>=24) c="warn" }
                a=o[i]; if (a<st) a=st; b=(nw[i]==""?NOW:nw[i]); x1=L+P*(a-st)/(en-st); x2=L+P*(b-st)/(en-st); if (x2-x1<2) x2=x1+2
                printf "<text class=\"lbl\" x=\"6\" y=\"%d\">%s</text><rect class=\"%s\" x=\"%.1f\" y=\"%d\" width=\"%.1f\" height=\"14\" rx=\"3\"><title>%s&#10;%s - %s</title></rect>", y+16, h(substr(nm[i],1,34)), c, x1, y+4, x2-x1, h(nm[i]), fmt(o[i]), fmt(nw[i]) }
            for (i=1;i<=nb;i++) if (bt[i]>=st) { x=L+P*(bt[i]-st)/(en-st); printf "<line class=\"boot\" x1=\"%.1f\" y1=\"30\" x2=\"%.1f\" y2=\"%d\"><title>boot %s</title></line>", x, x, H-14, fmt(bt[i]) }
            x=L+P*(NOW-st)/(en-st); printf "<line class=\"nowl\" x1=\"%.1f\" y1=\"28\" x2=\"%.1f\" y2=\"%d\"/>", x, x, H-14
            if (SUSPECT>0) { x=L+P*(SUSPECT-st)/(en-st); printf "<line class=\"suspect\" x1=\"%.1f\" y1=\"28\" x2=\"%.1f\" y2=\"%d\"/><text class=\"susp-t\" x=\"%.1f\" y=\"%d\">suspected start</text>", x, x, H-14, x+4, H-2 }
            print "</svg>" }' "$F_LOGS" "$F_BOOT" "$F_EV"
}

hist_svg() {   # label
    awk -F'\t' -v L="$1" '$1==L' "$F_HIST" | sort -t$'\t' -k2,2n | rawk -F'\t' '
        { n++; t[n]=$2; c[n]=$3 }
        END { if (n==0) exit; st=t[1]; en=t[n]+3600; b=3600; if (en-st > 14*86400) b=86400; if (en-st > 400*86400) { st=en-400*86400 }
              for (i=1;i<=n;i++) { if (t[i]<st) continue; k=int((t[i]-st)/b); v[k]+=c[i]; if (v[k]>mx) mx=v[k] }
              nb=int((en-st)/b)+1; W=1200; H=110; bw=(W-60)/nb
              printf "<svg class=\"tl\" viewBox=\"0 0 %d %d\"><text class=\"axis\" x=\"4\" y=\"12\">max %d / %s</text>", W, H, mx, (b==3600?"hour":"day")
              for (k=0;k<nb;k++) { hh=(mx?80*v[k]/mx:0); x=50+k*bw; if (v[k]==0) printf "<rect class=\"gap\" x=\"%.1f\" y=\"18\" width=\"%.2f\" height=\"80\"/>", x, bw
                  else printf "<rect class=\"hist\" x=\"%.1f\" y=\"%.1f\" width=\"%.2f\" height=\"%.1f\"><title>%s: %d</title></rect>", x, 98-hh, (bw>1.5?bw-0.5:bw), hh, fmt(st+k*b), v[k] }
              printf "<text class=\"axis\" x=\"50\" y=\"108\">%s</text><text class=\"axis\" x=\"%d\" y=\"108\" text-anchor=\"end\">%s</text></svg>", substr(fmt(st),1,10), W-10, substr(fmt(en),1,10) }'
}

gauge_svg() {
    awk -v s="$1" -v g="$2" 'BEGIN { c="#dc2626"; if (s>=90) c="#16a34a"; else if (s>=75) c="#65a30d"; else if (s>=60) c="#d97706"; else if (s>=40) c="#ea580c"
        circ=2*3.14159265*52; d=circ*(s<0?0:(s>100?100:s))/100
        printf "<svg class=\"gauge\" viewBox=\"0 0 140 140\" width=\"190\" height=\"190\" role=\"img\"><circle class=\"track\" cx=\"70\" cy=\"70\" r=\"52\" fill=\"none\" stroke-width=\"13\"/><circle cx=\"70\" cy=\"70\" r=\"52\" fill=\"none\" stroke=\"%s\" stroke-width=\"13\" stroke-linecap=\"round\" stroke-dasharray=\"%.1f %.1f\" transform=\"rotate(-90 70 70)\"/><text x=\"70\" y=\"72\" text-anchor=\"middle\" font-size=\"34\" font-weight=\"700\">%d</text><text x=\"70\" y=\"94\" text-anchor=\"middle\" font-size=\"14\" font-weight=\"600\">Grade %s</text></svg>", c, d, circ, s, g }'
}

write_report() {
    local R="$OUT/report.html"
    local ncrit nhigh ucn ucc ucp ucg
    ncrit=$(awk -F'\t' '$1=="Critical"' "$F_FIND" | grep -c .); nhigh=$(awk -F'\t' '$1=="High"' "$F_FIND" | grep -c .)
    ucn=$(grep -c . "$F_UC"); ucc=$(awk -F'\t' '$5=="Covered"' "$F_UC" | grep -c .); ucp=$(awk -F'\t' '$5=="Partial"' "$F_UC" | grep -c .); ucg=$(awk -F'\t' '$5=="Gap"' "$F_UC" | grep -c .)
    local ar; ar=$(log_row auth); local aoldest; aoldest=$(printf '%s' "$ar" | cut -f7)
    {
    printf '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="author" content="%s; co-author and contributor: %s"><meta name="generator" content="%s linux-log-gap-analysis.sh v%s (%s)">' "$AUTHOR" "$COAUTHOR" "$TOOL_ID" "$VERSION" "$REPO"
    printf '<title>Linux Logging Gap Analysis - %s</title><style>%s</style></head><body>' "$(hesc "$HOST")" "$REPORT_CSS"
    printf '<header class="top"><div class="wrap"><div class="brand">Linux Logging Gap Analysis &middot; Incident Response</div>'
    printf '<h1>%s</h1><div class="meta">%s &middot; kernel %s &middot; roles: %s<br>Collected %s by %s &middot; tool v%s</div></div></header>' \
        "$(hesc "$FQDN")" "$(hesc "$OS_NAME")" "$(hesc "$KERNEL")" "$(hesc "${ROLES:-none detected}")" "$(hesc "$RUN_START_TXT")" "$(hesc "$RUN_USER")" "$VERSION"
    printf '<main class="wrap"><nav class="toc"><a href="#summary">Summary</a><a href="#findings">Findings</a><a href="#timeline">Timeline</a><a href="#coverage">Detection coverage</a><a href="#siem">SIEM / Splunk</a><a href="#audit">auditd rules</a><a href="#logs">Log inventory</a><a href="#config">Logging configuration</a><a href="#events">Tampering events</a><a href="#access">Privileged access</a>'
    [ $DEEP -eq 1 ] && printf '<a href="#deep">Deep scan</a>'
    printf '<a href="#collection">Collection</a></nav>'
    # summary
    printf '<section id="summary" class="card"><h2>Summary</h2><p class="sub">Overall readiness of this host'"'"'s logging for incident response.</p><div class="grid-sum"><div>%s<div class="grade" style="text-align:center">%s%s</div></div><div>' "$(gauge_svg "$SCORE" "$GRADE")" "$LABEL" "$( [ $SCORE_CAPPED -eq 1 ] && echo ' (capped: critical tampering)')"
    rawk -F'\t' '{ r=($3>0)?$2/$3:0; col=(r>=0.85)?"var(--ok)":((r>=0.6)?"#65a30d":((r>=0.4)?"var(--warn)":"var(--bad)"))
        printf "<div class=\"area\"><div class=\"lbl\"><span>%s</span><span>%.1f / %d</span></div><div class=\"bar\"><span style=\"width:%.0f%%;background:%s\"></span></div><div class=\"note\">%s</div></div>", h($1), $2, $3, 100*r, col, h($4) }' "$F_AREA"
    printf '</div><div class="kpis">'
    printf '<div class="kpi"><div class="v" style="color:var(--crit)">%s</div><div class="k">Critical findings</div></div>' "$ncrit"
    printf '<div class="kpi"><div class="v" style="color:var(--high)">%s</div><div class="k">High findings</div></div>' "$nhigh"
    printf '<div class="kpi"><div class="v">%s / %s</div><div class="k">Use cases covered (partial %s, gap %s)</div></div>' "$ucc" "$ucn" "$ucp" "$ucg"
    printf '<div class="kpi"><div class="v">%s</div><div class="k">Auth log reaches back to</div></div>' "$( [ -n "$aoldest" ] && fmt_epoch "$aoldest" | cut -c1-10 || echo n/a)"
    printf '<div class="kpi"><div class="v">%s</div><div class="k">Tampering indicators</div></div>' "$(awk -F'\t' '$2=="Tampering"' "$F_FIND" | grep -c .)"
    printf '<div class="kpi"><div class="v">%s</div><div class="k">Accounts with root / sudo</div></div>' "$(awk -F'\t' '$1 !~ /^%/' "$F_PRIV" | cut -f1 | sort -u | grep -c .)"
    printf '</div></div><div class="verdict">%s</div></section>' "$(hesc "$(verdict)")"
    # findings
    printf '<section id="findings" class="card"><h2>Findings</h2><p class="sub">Sorted by severity. Each finding includes the evidence and a recommended action. Category <b>Access</b> does not change the score.</p>'
    printf '<input class="filter" data-table="tf" placeholder="Filter findings..."><div class="tw"><table class="t" id="tf"><thead><tr><th style="width:80px">Severity</th><th style="width:100px">Category</th><th style="width:32%%">Finding</th><th>Evidence</th><th style="width:26%%">Recommendation</th></tr></thead><tbody>'
    awk -F'\t' 'BEGIN{ r["Critical"]=5; r["High"]=4; r["Medium"]=3; r["Low"]=2; r["Info"]=1 } { print r[$1] "\t" $0 }' "$F_FIND" | sort -t$'\t' -k1,1nr -s | cut -f2- |
        rawk -F'\t' '{ m=($7!="")?" <span class=\"tag\">" h($7) "</span>":""; printf "<tr><td>%s</td><td class=\"nowrap\">%s</td><td><b>%s</b>%s<div class=\"small muted\">%s</div></td><td class=\"small\">%s</td><td class=\"small\">%s</td></tr>", badge($1,$1), h($2), h($3), m, h($4), h($5), h($6) }'
    printf '</tbody></table></div></section>'
    # timeline
    printf '<section id="timeline" class="card"><h2>Log coverage timeline</h2><p class="sub">Each bar spans the oldest to the newest entry of a log (all rotations). Green reaches back to the suspected start (or 7+ days), red does not. Dashed lines are boots, dots are tampering events.</p>'
    printf '<div class="legend"><span><i class="dot" style="background:#dc2626"></i>log deleted / cleared</span><span><i class="dot" style="background:#f97316"></i>audit rules changed</span><span><i class="dot" style="background:#9333ea"></i>logging service stopped</span><span><i class="dot" style="background:#facc15"></i>events lost</span><span><i class="dot" style="background:#0ea5e9"></i>other</span></div>'
    timeline_svg
    printf '</section>'
    # coverage
    printf '<section id="coverage" class="card"><h2>Detection coverage (MITRE ATT&amp;CK)</h2><p class="sub">Whether the current logging can support each detection / investigation use case on this host, whether the evidence reaches Splunk, and how far back the source log goes.</p>'
    printf '<input class="filter" data-table="tu" placeholder="Filter use cases..."><div class="tw"><table class="t" id="tu"><thead><tr><th>Use case</th><th>Local logging</th><th>Evidence sources</th><th>SIEM</th><th>History</th></tr></thead><tbody>'
    rawk -F'\t' '{ k=($10==1)?" <span class=\"tag\">key</span>":""; n=split($6,s,"; "); d=""; for (i=1;i<=n;i++) d=d "<div class=\"small\">" h(s[i]) "</div>"
        printf "<tr><td><b>%s</b>%s<div class=\"small muted\">%s &middot; %s &middot; %s</div></td><td>%s</td><td>%s</td><td>%s<div class=\"small muted\">%s</div></td><td class=\"nowrap\">%s</td></tr>", h($2), k, h($1), h($3), h($4), sbadge($5), d, sbadge($7), h($8), span($9) }' "$F_UC"
    printf '</tbody></table></div></section>'
    # SIEM
    printf '<section id="siem" class="card"><h2>SIEM forwarding</h2>'
    if [ $SPLUNK -eq 1 ]; then
        printf '<div class="kv"><div>Splunk home / version</div><div>%s / %s</div><div>splunkd running</div><div>%s</div><div>Indexers (outputs.conf)</div><div>%s</div><div>Deployment server</div><div>%s</div><div>splunkd.log output errors / blocked (last 20,000 lines)</div><div>%s / %s</div></div>' \
            "$(hesc "$SPLUNK_HOME")" "$(hesc "${SPLUNK_VER:-?}")" "$( [ $SPLUNK_RUN -eq 1 ] && echo yes || echo '<b style="color:var(--bad)">no</b>')" "$(hesc "${SPLUNK_SERVERS:-not found}")" "$(hesc "${SPLUNK_DS:-none}")" "${SPLUNK_ERR:-0}" "${SPLUNK_BLOCK:-0}"
        printf '<h3>Forwarding status per log</h3><div class="tw"><table class="t"><thead><tr><th>Log file</th><th>Status</th><th>Responsible stanza / rule</th></tr></thead><tbody>'
        rawk -F'\t' '{ printf "<tr><td class=\"mono\">%s</td><td>%s</td><td class=\"small mono\">%s</td></tr>", h($1), sbadge($2), h($3) }' "$F_SPF"
        printf '</tbody></table></div><h3>Input stanzas (monitor / batch / journald)</h3><div class="tw"><table class="t"><thead><tr><th>Stanza</th><th>State</th><th>Index</th><th>Sourcetype</th><th>Whitelist</th><th>Blacklist</th><th>File</th></tr></thead><tbody>'
        rawk -F'\t' '{ printf "<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"mono small\">%s</td><td class=\"mono small\">%s</td><td class=\"small mono\">%s</td></tr>", h($1), ($2=="1"?badge("Disabled","bad"):badge("Enabled","ok")), h($3), h($4), h(wj($5)), h(wj($6)), h($7) }' "$F_SP"
        printf '</tbody></table></div>'
    else
        printf '<p>No Splunk forwarder found on this host.</p>'
    fi
    printf '<div class="kv" style="margin-top:12px"><div>Syslog forwarding targets</div><div>%s</div><div>auditd remote (au-remote)</div><div>%s</div><div>Agents</div><div>%s</div></div></section>' \
        "$(hesc "${SYSLOG_FWD:-none}")" "$( [ $AUDISP_REMOTE -eq 1 ] && echo active || echo 'not active')" "$(awk -F'\t' '{ printf "%s (%s, %s); ", $2, $1, $3 }' "$F_AGENT" | sed 's/&/\&amp;/g; s/</\&lt;/g')"
    # audit rules
    printf '<section id="audit" class="card"><h2>auditd rules against the IR baseline</h2><p class="sub">auditd running: <b>%s</b> &middot; kernel enabled flag: <b>%s</b> &middot; rules loaded / on disk: <b>%s / %s</b> &middot; lost events: <b>%s</b> &middot; backlog limit: <b>%s</b>. Baseline assembled from CIS benchmarks, ASD and community IR rule sets.</p>' \
        "$( [ $AUD_RUNNING -eq 1 ] && echo yes || echo no)" "${AUD_ENABLED:-unknown}" "$AUD_RULES_LOADED" "$AUD_RULES_PERSIST" "${AUD_LOST:-unknown}" "${AUD_BACKLOG:-unknown}"
    printf '<input class="filter" data-table="ta" placeholder="Filter rules..."><div class="tw"><table class="t" id="ta"><thead><tr><th>ID</th><th>Coverage</th><th>ATT&amp;CK</th><th>Status</th><th>Loaded</th><th>On disk</th><th>Why it matters / example rule</th></tr></thead><tbody>'
    while IFS=$'\037' read -r id name mitre st inl inp why key; do
        printf '<tr><td>%s</td><td><b>%s</b>%s</td><td class="small">%s</td><td>%s</td><td>%s</td><td>%s</td><td class="small">%s<div class="mono muted">%s</div></td></tr>' "$id" "$(hesc "$name")" "$( [ "$key" = 1 ] && echo ' <span class="tag">key</span>')" "$mitre" \
            "$(rawk 'BEGIN{ print sbadge(S) }' -v S="$( [ "$st" = OK ] && echo OK || { [ "$st" = 'Persistent only' ] && echo 'Persistent only' || echo "$st"; })")" "$( [ "$inl" = 1 ] && echo yes || echo -)" "$( [ "$inp" = 1 ] && echo yes || echo -)" "$(hesc "$why")" "$( [ "$st" != OK ] && hesc "$(AUDIT_RULE_SAMPLE "$id")")"
    done < <(tr '\t' '\037' < "$F_AR")
    printf '</tbody></table></div></section>'
    # log inventory
    printf '<section id="logs" class="card"><h2>Log inventory</h2><p class="sub">All rotations are included in Oldest / Size. Capacity estimates how much history the rotation settings can hold at the current rate.</p>'
    printf '<input class="filter" data-table="tl" placeholder="Filter logs..."><div class="tw"><table class="t" id="tl"><thead><tr><th>Log</th><th>Status</th><th>Oldest</th><th>Newest</th><th>History</th><th>Files</th><th>Size</th><th>Lines/h</th><th>Rotation</th><th>Capacity</th></tr></thead><tbody>'
    rawk -F'\t' '{ st=($4=="OK")?"OK":$4; note=($15!="")?"<div class=\"small\" style=\"color:var(--bad)\">" h($15) "</div>":""
        printf "<tr><td><b>%s</b><div class=\"mono muted\">%s</div><div class=\"small muted\">%s</div>%s</td><td>%s</td><td class=\"small nowrap\">%s</td><td class=\"small nowrap\">%s</td><td class=\"nowrap\">%s</td><td>%s</td><td class=\"nowrap\">%s</td><td>%s</td><td class=\"small\">%s</td><td class=\"nowrap\">%s</td></tr>", h($2), h($3), h($14), note, sbadge(st), fmt($7), fmt($8), span($11), $5, size($6), $10, h($12), ($13==""?"":span($13*3600)) }' "$F_LOGS"
    printf '</tbody></table></div></section>'
    # configuration
    printf '<section id="config" class="card"><h2>Logging configuration</h2><div class="tw"><table class="t"><thead><tr><th>Setting</th><th>Value</th><th>Assessment</th></tr></thead><tbody>'
    rawk -F'\t' '{ printf "<tr><td>%s</td><td class=\"mono\">%s</td><td>%s</td></tr>", h($1), h($2), sbadge($3) }' "$F_CFG"
    printf '</tbody></table></div></section>'
    # events
    printf '<section id="events" class="card"><h2>Tampering-relevant events</h2><p class="sub">Audit configuration changes, logging service stops outside a shutdown, lost events, time changes, deleted-but-open log files (boots omitted).</p>'
    printf '<input class="filter" data-table="te" placeholder="Filter events..."><div class="tw"><table class="t" id="te"><thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Event</th><th>Details</th></tr></thead><tbody>'
    awk -F'\t' '$4!="boot"' "$F_EV" | sort -t$'\t' -k1,1nr | head -n 1000 | rawk -F'\t' '{ printf "<tr><td class=\"nowrap small\">%s</td><td>%s</td><td class=\"small\">%s</td><td>%s</td><td class=\"small mono\">%s</td></tr>", fmt($1), badge($2,$2), h($3), h($5), h($6); n++ } END { if (!n) print "<tr><td colspan=\"5\" class=\"muted\">No tampering-relevant events found in the available logs.</td></tr>" }'
    printf '</tbody></table></div></section>'
    # access
    printf '<section id="access" class="card"><h2>Privileged access and logons</h2><p class="sub">Who can become root on this host, local accounts that can log on, SSH keys, and every account with logon evidence (wtmp + auth log).</p><div class="kv">'
    printf '<div>Accounts / with login shell</div><div>%s / %s</div>' "$(grep -c . "$F_USERS")" "$(awk -F'\t' '$6==1' "$F_USERS" | grep -c .)"
    printf '<div>sshd PermitRootLogin / PasswordAuthentication / LogLevel</div><div>%s / %s / %s</div>' "$(hesc "${SSHD_ROOT:-n/a}")" "$(hesc "${SSHD_PWAUTH:-n/a}")" "$(hesc "${SSHD_LOGLEVEL:-n/a}")"
    printf '<div>Logged on now</div><div>%s</div></div>' "$(awk -F'\t' '{ printf "%s (%s since %s%s); ", $1, $2, $3, ($4!=""?" from " $4:"") }' "$F_SESS" | sed 's/&/\&amp;/g; s/</\&lt;/g')"
    printf '<h3>Root and sudo rights</h3><input class="filter" data-table="tpr" placeholder="Filter..."><div class="tw"><table class="t" id="tpr"><thead><tr><th>Account</th><th>Granted by</th><th>Detail</th><th>Password</th><th>Shell</th></tr></thead><tbody>'
    rawk -F'\t' '{ fi=(FILENAME==ARGV[1])?1:((FILENAME==ARGV[2])?2:3) } fi==1 { pw[$1]=$7; sh[$1]=$5; next } { printf "<tr><td><b>%s</b></td><td>%s</td><td class=\"small\">%s</td><td class=\"small\">%s</td><td class=\"mono small\">%s</td></tr>", h($1), h($2), h($3), h(pw[$1]), h(sh[$1]) }' "$F_USERS" "$F_PRIV"
    printf '</tbody></table></div>'
    printf '<h3>Accounts with a login shell</h3><div class="tw"><table class="t"><thead><tr><th>Account</th><th>UID</th><th>Shell</th><th>Password</th><th>Password changed</th><th>Last login (lastlog)</th><th>SSH keys</th></tr></thead><tbody>'
    rawk -F'\t' '{ fi=(FILENAME==ARGV[1])?1:((FILENAME==ARGV[2])?2:3) } fi==1 { ll[$1]=$2; next } fi==2 { k[$1]+=$3; next }
        $6==1 { pc=($7=="EMPTY")?badge("EMPTY","bad"):h($7); printf "<tr><td><b>%s</b></td><td>%s</td><td class=\"mono small\">%s</td><td>%s</td><td class=\"small nowrap\">%s</td><td class=\"small nowrap\">%s</td><td>%s</td></tr>", h($1), $2, h($5), pc, ($8==""?"":substr(fmt($8),1,10)), fmt(ll[$1]), (k[$1]?k[$1]:"") }' "$W/lastlog.tsv" "$F_KEYS" "$F_USERS"
    printf '</tbody></table></div>'
    if [ -s "$F_KEYS" ]; then
        printf '<h3>SSH authorized keys</h3><div class="tw"><table class="t"><thead><tr><th>Account</th><th>File</th><th>Keys</th><th>Modified</th><th>Key comments / options</th></tr></thead><tbody>'
        rawk -F'\t' '{ flag=(SUSPECT>0 && $4>=SUSPECT)?" " badge("after suspected start","bad"):""; printf "<tr><td><b>%s</b></td><td class=\"mono small\">%s</td><td>%s</td><td class=\"small nowrap\">%s%s</td><td class=\"small mono\">%s</td></tr>", h($1), h($2), $3, fmt($4), flag, h($5) }' "$F_KEYS"
        printf '</tbody></table></div>'
    fi
    printf '<h3>Accounts with logon evidence</h3><p class="small muted">wtmp (all rotations) and auth log "Accepted ..." lines. Public source addresses are marked.</p><input class="filter" data-table="tlo" placeholder="Filter accounts..."><div class="tw"><table class="t" id="tlo"><thead><tr><th>Account</th><th>Root / sudo</th><th>Logons</th><th>First seen</th><th>Last seen</th><th>Sources</th><th>Method / terminal</th></tr></thead><tbody>'
    rawk -F'\t' '{ fi=(FILENAME==ARGV[1])?1:((FILENAME==ARGV[2])?2:3) } fi==1 { if ($1 !~ /^%/) pr[$1]=pr[$1] (pr[$1]==""?"":", ") $2; next }
        { n=split($5,a,"; "); s=""; for (i=1;i<=n && i<=8;i++) { split(a[i],b,"="); t=h(b[1]) " (" b[2] ")"; if (ispub(b[1])) t="<b style=\"color:var(--bad)\">" t " public</b>"; s=s (s==""?"":"<br>") t }
          pv=(pr[$1]!="")?badge("Admin","bad") "<div class=\"small muted\">" h(pr[$1]) "</div>":""
          flag=(SUSPECT>0 && $3>=SUSPECT)?" " badge("first after suspected start","warn"):""
          printf "<tr><td><b>%s</b>%s</td><td>%s</td><td>%s</td><td class=\"small nowrap\">%s</td><td class=\"small nowrap\">%s</td><td class=\"small mono\">%s</td><td class=\"small\">%s<div class=\"muted\">%s</div></td></tr>", h($1), flag, pv, $2, fmt($3), fmt($4), s, h($6), h($7); c++ }
        END { if (!c) print "<tr><td colspan=\"7\" class=\"muted\">No logon evidence found.</td></tr>" }' "$F_PRIV" "$F_LOGON"
    printf '</tbody></table></div>'
    printf '<h3>Failed logons by source</h3><div class="tw"><table class="t"><thead><tr><th>Source</th><th>Failures</th><th>Accounts</th><th>Sample accounts</th><th>Type</th><th>First</th><th>Last</th></tr></thead><tbody>'
    head -n 30 "$F_FAIL" | rawk -F'\t' '{ s=h($1); if (ispub($1)) s="<b>" s "</b> " badge("public","bad"); printf "<tr><td class=\"mono\">%s</td><td>%s</td><td>%s</td><td class=\"small\">%s</td><td class=\"small\">%s</td><td class=\"small nowrap\">%s</td><td class=\"small nowrap\">%s</td></tr>", s, $2, $3, h($4), h($5), fmt($6), fmt($7); c++ } END { if (!c) print "<tr><td colspan=\"7\" class=\"muted\">No failed logons found.</td></tr>" }'
    printf '</tbody></table></div>'
    printf '<h3>Account and group changes</h3><div class="tw"><table class="t"><thead><tr><th>Time</th><th>Change</th><th>Account</th><th>Group</th><th>Detail</th><th>Source</th></tr></thead><tbody>'
    sort -t$'\t' -k1,1nr "$F_CHG" | head -n 300 | rawk -F'\t' '{ flag=(SUSPECT>0 && $1>=SUSPECT)?" " badge("after suspected start","bad"):""; printf "<tr><td class=\"small nowrap\">%s</td><td>%s%s</td><td><b>%s</b></td><td>%s</td><td class=\"small\">%s</td><td class=\"small\">%s</td></tr>", fmt($1), h($2), flag, h($3), h($4), h($5), h($6); c++ } END { if (!c) print "<tr><td colspan=\"6\" class=\"muted\">No account changes found in the available logs.</td></tr>" }'
    printf '</tbody></table></div>'
    printf '<h3>sudo / su usage</h3><div class="tw"><table class="t"><thead><tr><th>Account</th><th>Commands run</th><th>Denied</th><th>Last use</th><th>Last commands</th></tr></thead><tbody>'
    sort -t$'\t' -k1,1n "$F_SUDO" | rawk -F'\t' '{ u=$2; if ($3=="ok") ok[u]++; else den[u]++; if ($1>l[u]) l[u]=$1; lc[u]=(length(lc[u])<300)?lc[u] (lc[u]==""?"":" | ") $5:lc[u]; seen[u]=1 }
        END { for (u in seen) printf "<tr><td><b>%s</b></td><td>%d</td><td>%s</td><td class=\"small nowrap\">%s</td><td class=\"small mono\">%s</td></tr>", h(u), ok[u], (den[u]?badge(den[u],"warn"):""), fmt(l[u]), h(substr(lc[u],1,300)) }'
    printf '</tbody></table></div></section>'
    # deep
    if [ $DEEP -eq 1 ]; then
        printf '<section id="deep" class="card"><h2>Deep scan</h2><p class="sub">Complete read of the key logs (max %s lines each). Audit serial gaps indicate removed or dropped records; silences longer than %s minutes and backwards time jumps are listed. Red shading in the histograms marks hours / days without events.</p>' "$DEEP_MAX" "$GAP_MIN"
        while IFS=$'\037' read -r lbl n first last back miss sg trunc secs; do
            printf '<h3>%s</h3><p class="small muted">%s lines read in %s s %s; %s - %s; %s backwards jump(s)%s</p>' "$(hesc "$lbl")" "$n" "${secs:-?}" "$trunc" "$(fmt_epoch "$first")" "$(fmt_epoch "$last")" "$back" "$( [ "$lbl" = 'Audit (auditd)' ] && echo "; $miss record(s) missing in $sg serial gap(s)")"
            hist_svg "$lbl"
        done < <(tr '\t' '\037' < "$F_DEEP")
        printf '<h3>Gaps and anomalies</h3><div class="tw"><table class="t"><thead><tr><th>Log</th><th>Type</th><th>From</th><th>To</th><th>Size</th></tr></thead><tbody>'
        head -n 300 "$F_GAPS" | rawk -F'\t' '{ sz=($2=="serial")?$5 " record(s)":$5 " min"; printf "<tr><td>%s</td><td>%s</td><td class=\"small nowrap\">%s</td><td class=\"small nowrap\">%s</td><td>%s</td></tr>", h($1), h($2), fmt($3), fmt($4), sz; c++ } END { if (!c) print "<tr><td colspan=\"5\" class=\"muted\">No gaps found.</td></tr>" }'
        printf '</tbody></table></div><p class="small">wtmp: %s zeroed / empty record(s), %s backwards jump(s). journalctl --verify problems: %s.</p>' "${WTMP_BAD:-n/a}" "${WTMP_ORDER:-n/a}" "${JVERIFY:-not run}"
        printf '<h3>Anti-logging commands (%s patterns)</h3><div class="tw"><table class="t"><thead><tr><th>Time</th><th>Source</th><th>Pattern</th><th>Command</th></tr></thead><tbody>' "${DEEP_PATTERNS:-0}"
        sort -t$'\t' -k1,1n "$F_CMD" | rawk -F'\t' '{ printf "<tr><td class=\"small nowrap\">%s</td><td class=\"small\">%s</td><td>%s</td><td class=\"mono small\">%s</td></tr>", ($1>0?fmt($1):"(no timestamp)"), h($2), h($3), h($4); c++ } END { if (!c) print "<tr><td colspan=\"4\" class=\"muted\">No anti-logging commands found.</td></tr>" }'
        printf '</tbody></table></div></section>'
    fi
    # collection
    printf '<section id="collection" class="card"><h2>Collection details and limitations</h2><div class="kv">'
    printf '<div>Host</div><div>%s (%s)</div><div>Operating system</div><div>%s, kernel %s, %s%s</div>' "$(hesc "$FQDN")" "$(hesc "$IPS")" "$(hesc "$OS_NAME")" "$(hesc "$KERNEL")" "$ARCH" "$( [ -n "$VIRT" ] && echo ", $VIRT")"
    printf '<div>Time zone / last boot</div><div>%s / %s</div><div>Run as</div><div>%s (root: %s)</div>' "$(hesc "$TZNAME")" "$(fmt_epoch "$BOOT")" "$(hesc "$RUN_USER")" "$( [ $IS_ROOT -eq 1 ] && echo yes || echo no)"
    printf '<div>SELinux / AppArmor</div><div>%s</div><div>Suspected start</div><div>%s</div><div>Deep scan</div><div>%s</div>' "$(hesc "$SELINUX")" "$( [ -n "$SUSPECT" ] && fmt_epoch "$SUSPECT" || echo 'not given')" "$( [ $DEEP -eq 1 ] && echo yes || echo no)"
    printf '<div>Collection started / duration</div><div>%s / %s s</div><div>Author</div><div>secamin &middot; <a href="https://github.com/secamin">github.com/secamin</a> (SIEM Detection Content)</div><div>Co-author and contributor</div><div>HXM14 &middot; <a href="https://github.com/HXM14">github.com/HXM14</a></div><div>Tool</div><div>linux-log-gap-analysis.sh v%s <span class="mono small">SHA-256 %s</span></div></div>' "$(hesc "$RUN_START_TXT")" "$(( $(date +%s) - NOW ))" "$VERSION" "$(sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1)"
    printf '<h3>Workflow</h3><div class="tw"><table class="t"><thead><tr><th>Check</th><th>Status</th><th>Note</th></tr></thead><tbody>'
    rawk -F'\t' '{ printf "<tr><td>%s</td><td>%s</td><td class=\"small\">%s</td></tr>", h($1), h($2), h($3) }' "$F_WF"
    printf '</tbody></table></div><h3>Limitations</h3><ul class="small">'
    printf '<li>The script runs on a possibly compromised host: a rootkit (kernel module or ld.so.preload) can hide files, processes and log lines from it. A clean result is not proof that the host is clean.</li>'
    printf '<li>Running the script itself creates events (sudo in the auth log, EXECVE records) at the collection time shown above.</li>'
    printf '<li>Syslog lines without a year are assigned to the current year (or the previous year if that would be in the future); local time zone changes inside a log are not corrected.</li>'
    printf '<li>Splunk filtering is evaluated from inputs.conf on this host. Index-time filtering (props / transforms on indexers or heavy forwarders) is not visible from here. Syslog / agent forwarding can only be detected, not verified per log.</li>'
    printf '<li>Audit serial gaps can also come from events suppressed by "never" rules or lost under load; check the lost counter before concluding deletion.</li>'
    printf '</ul></section></main><footer>Linux Logging Gap Analysis v%s &middot; generated %s &middot; read-only collection<br>by <a href="https://github.com/secamin">secamin</a> &middot; co-author and contributor <a href="https://github.com/HXM14">HXM14</a> &middot; secamin/log-gap-analysis</footer><script>%s</script></body></html>' "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S')" "$REPORT_JS"
    } > "$R"
}

tsv2csv() {   # tsv2csv TSV OUT "header1,header2,..." [epoch columns e.g. "1 3"]
    local tsv="$1" out="$2" hdr="$3" ec="${4:-}"
    { printf '%s\n' "$hdr"
      awkx -F'\t' -v EC="$ec" 'BEGIN { n=split(EC,a," "); for (i=1;i<=n;i++) epc[a[i]]=1 }
          { line=""; for (i=1;i<=NF;i++) { v=$i; if ((i in epc) && v ~ /^[0-9]+$/) v=fmt(v); gsub(/"/,"\"\"",v); line=line (i>1?",":"") "\"" v "\"" }; print line }' "$tsv"
    } > "$out"
}
tsv2json() {  # tsv2json TSV "name1,name2,..." [epoch columns]
    awkx -F'\t' -v N="$2" -v EC="${3:-}" 'function js(s) { gsub("\036"," || ",s); gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\t/,"\\t",s); gsub(/[\001-\037]/,"",s); return "\"" s "\"" }
        BEGIN { k=split(N,nm,","); n=split(EC,a," "); for (i=1;i<=n;i++) epc[a[i]]=1; printf "[" }
        { printf "%s{", (NR>1?",":""); for (i=1;i<=k;i++) { v=$i; if ((i in epc) && v ~ /^[0-9]+$/) v=fmt(v); printf "%s%s:%s", (i>1?",":""), js(nm[i]), js(v) }; printf "}" }
        END { printf "]" }' "$1"
}

export_results() {
    tsv2csv "$F_FIND" "$OUT/findings.csv" 'Severity,Category,Finding,Detail,Evidence,Recommendation,Mitre'
    tsv2csv "$F_UC" "$OUT/usecases.csv" 'Id,UseCase,Tactic,Mitre,Local,Sources,SIEM,SIEMDetail,HistorySeconds,Key'
    tsv2csv "$F_LOGS" "$OUT/logs.csv" 'Kind,Log,Path,Status,Files,Bytes,Oldest,Newest,Lines,LinesPerHour,SpanSeconds,Rotation,CapacityHours,Purpose,Note' '7 8'
    tsv2csv "$F_AR" "$OUT/auditrules.csv" 'Id,Coverage,Mitre,Status,Loaded,OnDisk,Why,Key'
    tsv2csv "$F_SPF" "$OUT/splunk_inputs.csv" 'LogFile,Status,Rule'
    tsv2csv "$F_EV" "$OUT/tampering_events.csv" 'Time,Severity,Source,Kind,Event,Detail' '1'
    tsv2csv "$F_PRIV" "$OUT/privileged_accounts.csv" 'Account,GrantedBy,Detail'
    tsv2csv "$F_LOGON" "$OUT/logons.csv" 'Account,Logons,FirstSeen,LastSeen,Sources,Methods,Terminals' '3 4'
    tsv2csv "$F_FAIL" "$OUT/failed_logons.csv" 'Source,Failures,Accounts,SampleAccounts,Types,First,Last' '6 7'
    tsv2csv "$F_CHG" "$OUT/account_changes.csv" 'Time,Change,Account,Group,Detail,Source' '1'
    tsv2csv "$F_KEYS" "$OUT/ssh_keys.csv" 'Account,File,Keys,Modified,Comments' '4'
    tsv2csv "$F_SUDO" "$OUT/sudo_usage.csv" 'Time,Account,Result,RunAs,Command' '1'
    [ $DEEP -eq 1 ] && tsv2csv "$F_CMD" "$OUT/anti_logging_commands.csv" 'Time,Source,Pattern,Command' '1'
    {
        printf '{"tool":"linux-log-gap-analysis","toolId":"secamin/log-gap-analysis","author":"secamin","coAuthor":"HXM14","repository":"https://github.com/secamin","coAuthorRepository":"https://github.com/HXM14","version":"%s","collected":"%s","host":"%s","fqdn":"%s",' "$VERSION" "$(json_str "$RUN_START_TXT")" "$(json_str "$HOST")" "$(json_str "$FQDN")"
        printf '"system":{"os":"%s","kernel":"%s","arch":"%s","roles":"%s","timezone":"%s","boot":"%s","root":%s,"selinux":"%s"},' "$(json_str "$OS_NAME")" "$(json_str "$KERNEL")" "$ARCH" "$(json_str "$ROLES")" "$(json_str "$TZNAME")" "$(fmt_epoch "$BOOT")" "$( [ $IS_ROOT -eq 1 ] && echo true || echo false)" "$(json_str "$SELINUX")"
        printf '"suspectedStart":"%s","deepScan":%s,' "$( [ -n "$SUSPECT" ] && fmt_epoch "$SUSPECT")" "$( [ $DEEP -eq 1 ] && echo true || echo false)"
        printf '"score":{"total":%s,"grade":"%s","label":"%s","capped":%s,"areas":%s},' "$SCORE" "$GRADE" "$LABEL" "$( [ $SCORE_CAPPED -eq 1 ] && echo true || echo false)" "$(tsv2json "$F_AREA" 'name,score,max,note')"
        printf '"verdict":"%s",' "$(json_str "$(verdict)")"
        printf '"findings":%s,' "$(tsv2json "$F_FIND" 'severity,category,title,detail,evidence,recommendation,mitre')"
        printf '"useCases":%s,' "$(tsv2json "$F_UC" 'id,name,tactic,mitre,status,sources,siem,siemDetail,historySeconds,key')"
        printf '"logs":%s,' "$(tsv2json "$F_LOGS" 'kind,name,path,status,files,bytes,oldest,newest,lines,linesPerHour,spanSeconds,rotation,capacityHours,purpose,note' '7 8')"
        printf '"auditd":{"installed":%s,"running":%s,"enabledFlag":"%s","lost":"%s","rulesLoaded":%s,"rulesOnDisk":%s,"baseline":%s},' "$AUD_INSTALLED" "$AUD_RUNNING" "${AUD_ENABLED:-}" "${AUD_LOST:-}" "$AUD_RULES_LOADED" "$AUD_RULES_PERSIST" "$(tsv2json "$F_AR" 'id,name,mitre,status,loaded,onDisk,why,key')"
        printf '"configuration":%s,"agents":%s,' "$(tsv2json "$F_CFG" 'setting,value,state')" "$(tsv2json "$F_AGENT" 'type,name,state')"
        printf '"splunk":{"installed":%s,"home":"%s","version":"%s","running":%s,"servers":"%s","inputs":%s,"files":%s},' "$SPLUNK" "$(json_str "$SPLUNK_HOME")" "$(json_str "$SPLUNK_VER")" "$SPLUNK_RUN" "$(json_str "$SPLUNK_SERVERS")" "$(tsv2json "$F_SP" 'stanza,disabled,index,sourcetype,whitelist,blacklist,file')" "$(tsv2json "$F_SPF" 'path,status,rule')"
        printf '"tamperingEvents":%s,' "$(tsv2json "$F_EV" 'time,severity,source,kind,title,detail' '1')"
        printf '"access":{"privileged":%s,"logons":%s,"failedLogons":%s,"accountChanges":%s,"sshKeys":%s,"sessions":%s},' "$(tsv2json "$F_PRIV" 'account,grantedBy,detail')" "$(tsv2json "$F_LOGON" 'account,logons,first,last,sources,methods,terminals' '3 4')" "$(tsv2json "$F_FAIL" 'source,failures,accounts,sample,types,first,last' '6 7')" "$(tsv2json "$F_CHG" 'time,change,account,group,detail,source' '1')" "$(tsv2json "$F_KEYS" 'account,file,keys,modified,comments' '4')" "$(tsv2json "$F_SESS" 'user,tty,since,from')"
        printf '"deepScan":{"logs":%s,"gaps":%s,"commands":%s},' "$(tsv2json "$F_DEEP" 'log,lines,first,last,backwards,serialMissing,serialGaps,truncated,seconds' '3 4')" "$(tsv2json "$F_GAPS" 'log,type,from,to,size' '3 4')" "$(tsv2json "$F_CMD" 'time,source,pattern,command' '1')"
        printf '"workflow":%s}\n' "$(tsv2json "$F_WF" 'check,status,note')"
    } > "$OUT/results.json"
}

# =====================================================================================================
#  Main
# =====================================================================================================
phase() {   # phase NAME function
    local name="$1"; shift
    if ! "$@"; then step ERROR "$name returned an error"; add_wf "$name" 'Error' 'see collection.log'; fi
}
printf '\n  Linux Logging Gap Analysis v%s  -  %s\n  by %s (%s)  -  co-author and contributor %s (%s)\n  Output: %s\n\n' "$VERSION" "$HOST" "$AUTHOR" "$REPO" "$COAUTHOR" "$COAUTHOR_REPO" "$OUT" >&2
SCORE=0; GRADE=F; LABEL=''; SCORE_CAPPED=0; CRIT_TAMPER=0; DELETED_OPEN=''; LOG_IMMUTABLE=''; KERNEL_AUDIT_OFF=0; WTMP_BAD=0; WTMP_ORDER=0; JVERIFY=''
phase 'System profile' collect_system
phase 'Log inventory' collect_logs
phase 'auditd' collect_audit
phase 'Logging configuration' collect_config
phase 'SIEM forwarding' collect_siem
phase 'Tampering evidence' collect_tamper
phase 'Privileged access and logons' collect_access
if [ $DEEP -eq 1 ]; then phase 'Deep scan' collect_deep
else add_wf 'Deep scan' 'Skipped' 'Use -d for time gaps, audit serial gaps, wtmp integrity and anti-logging commands'; fi
evaluate_usecases
build_findings
access_findings
compute_score
step OK "Score $SCORE/100 (grade $GRADE), $(grep -c . "$F_FIND") finding(s)"
step STEP 'Writing report'
write_report
export_results
rm -rf "$W"
step OK "Report: $OUT/report.html"
( cd "$OUT" && find . -type f ! -name manifest_sha256.txt -print0 | sort -z | xargs -0 sha256sum > manifest_sha256.txt 2>/dev/null )

printf '\n' >&2
c=$c_red; [ "$SCORE" -ge 75 ] && c=$c_green || { [ "$SCORE" -ge 60 ] && c=$c_yellow; }
printf '  %sIR readiness: %s/100  grade %s (%s)%s\n' "$c" "$SCORE" "$GRADE" "$LABEL" "$c_reset" >&2
{ grep -E '^"Critical"' "$OUT/findings.csv"; grep -E '^"High"' "$OUT/findings.csv"; } | head -n 10 | awk -F'","' -v r="$c_red" -v y="$c_yellow" -v z="$c_reset" '{ s=$1; gsub(/"/,"",s); printf "  %s[%s] %s%s\n", (s=="Critical"?r:y), s, $3, z }' >&2
printf '  Report: %s/report.html\n\n' "$OUT" >&2
