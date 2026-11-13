#!/bin/sh
# Copyright 2026 Uddeshya Kumar
# SPDX-License-Identifier: Apache-2.0
#
# collect-host.sh: read-only Linux host collector for `verdict import host`.
#
# Run it on the host, or pipe it over your own ssh session:
#
#   ssh admin@host 'sh -s' < scripts/collect-host.sh > host.json
#
# It prints one JSON document on stdout and nothing else. It does not write
# files, install packages, start or restart services, open network
# connections, read private keys, /etc/shadow, or environment variables, or
# print command output wholesale. It reads the package database, os-release,
# the socket table, systemd unit state, and sshd configuration.
#
# An sshd that no package database owns (a source build) is also read with
# `sshd -V`; its OpenSSH version becomes a "binary" entry that Verdict imports
# at medium confidence: evidence for affected, never for not_affected. See
# "source-built sshd" below.
#
# A fact is omitted when the command that would observe it is missing,
# fails, or cannot see enough (for example, socket owners without root).
# An omitted fact is unknown to Verdict. No default is filled in.
#
# Run as root for negative facts: without root, other users' socket owners
# are hidden, so "sshd is not listening" cannot be observed.

set -u
LC_ALL=C
export LC_ALL
PATH=/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}
export PATH

NOTES=""
note() {
  NOTES="${NOTES}$1
"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

# Shared awk helpers. esc() makes a JSON string body; enc() percent-encodes
# the package-URL reserved characters; bad() rejects whitespace and controls.
AWK_LIB='
function init(   i) {
  for (i = 1; i < 32; i++) CTRL[sprintf("%c", i)] = sprintf("\\u%04x", i)
  PCT["%"] = "%25"; PCT["@"] = "%40"; PCT["?"] = "%3F"; PCT["#"] = "%23"
  PCT["/"] = "%2F"; PCT["&"] = "%26"; PCT["="] = "%3D"; PCT[" "] = "%20"
}
function esc(s,   i, c, out, n) {
  out = ""
  n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\\") out = out "\\\\"
    else if (c == "\"") out = out "\\\""
    else if (c in CTRL) out = out CTRL[c]
    else out = out c
  }
  return out
}
function enc(s,   i, c, out, n) {
  out = ""
  n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c in PCT) out = out PCT[c]
    else out = out c
  }
  return out
}
function bad(s) {
  return s == "" || s ~ /[[:space:][:cntrl:]]/
}
function unparsed(mgr, line) {
  print "U {\"manager\":\"" mgr "\",\"line\":\"" esc(line) "\"}"
}
function pkg(mgr, name, version, purl) {
  print "P {\"manager\":\"" mgr "\",\"name\":\"" esc(name) "\",\"version\":\"" esc(version) "\",\"purl\":\"" esc(purl) "\"}"
}
function binpkg(name, version, purl, path) {
  print "P {\"manager\":\"binary\",\"name\":\"" esc(name) "\",\"version\":\"" esc(version) "\",\"purl\":\"" esc(purl) "\",\"path\":\"" esc(path) "\",\"source\":\"binary_version\"}"
}
'

# jstr prints its argument as a quoted JSON string.
jstr() {
  JV=$1 awk "$AWK_LIB"'BEGIN { init(); printf "\"%s\"", esc(ENVIRON["JV"]) }'
}

# ---------------------------------------------------------------- identity

HOSTNAME_V=""
if [ -r /proc/sys/kernel/hostname ]; then
  HOSTNAME_V=$(cat /proc/sys/kernel/hostname 2>/dev/null)
fi
if [ -z "$HOSTNAME_V" ]; then
  HOSTNAME_V=$(uname -n 2>/dev/null)
fi
COLLECTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)

# os-release is parsed, never sourced: sourcing would execute it.
OS_ID=""
OS_VERSION_ID=""
for f in /etc/os-release /usr/lib/os-release; do
  [ -r "$f" ] || continue
  OS_ID=$(awk -F= '$1 == "ID" { v = $2; gsub(/^["'\'']|["'\'']$/, "", v); print v; exit }' "$f")
  OS_VERSION_ID=$(awk -F= '$1 == "VERSION_ID" { v = $2; gsub(/^["'\'']|["'\'']$/, "", v); print v; exit }' "$f")
  break
done
case $OS_ID in *[!a-z0-9._-]*) note "os-release ID has unexpected characters; ignored"; OS_ID="" ;; esac
case $OS_VERSION_ID in *[!A-Za-z0-9._~-]*) note "os-release VERSION_ID has unexpected characters; ignored"; OS_VERSION_ID="" ;; esac
DISTRO=""
if [ -n "$OS_ID" ] && [ -n "$OS_VERSION_ID" ]; then
  DISTRO="$OS_ID-$OS_VERSION_ID"
fi

# ---------------------------------------------------------------- packages

PKG_OUT=""
add_pkg_out() {
  PKG_OUT="${PKG_OUT}$1
"
}

if have dpkg-query && [ -e /var/lib/dpkg/status ]; then
  if out=$(dpkg-query -W -f='${Status}\t${Package}\t${Version}\t${Architecture}\n' 2>/dev/null); then
    add_pkg_out "$(printf '%s\n' "$out" | ID="$OS_ID" DISTRO="$DISTRO" awk -F '\t' "$AWK_LIB"'
      BEGIN { init(); ns = ENVIRON["ID"]; distro = ENVIRON["DISTRO"] }
      $0 == "" { next }
      {
        n = split($1, st, " ")
        if (n == 3 && (st[3] == "not-installed" || st[3] == "config-files")) next
        if (NF != 4 || n != 3 || bad($2) || bad($3) || bad($4)) { unparsed("dpkg", $0); next }
        p = "pkg:deb/" (ns != "" ? enc(ns) "/" : "") enc($2) "@" enc($3) "?arch=" enc($4)
        if (distro != "") p = p "&distro=" enc(distro)
        pkg("dpkg", $2, $3, p)
      }')"
  else
    add_pkg_out "U {\"manager\":\"dpkg\",\"line\":\"dpkg-query failed\"}"
    note "dpkg-query failed; package list is incomplete"
  fi
fi

if have rpm && { [ -d /var/lib/rpm ] || [ -d /usr/lib/sysimage/rpm ]; }; then
  if out=$(rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' 2>/dev/null); then
    add_pkg_out "$(printf '%s\n' "$out" | ID="$OS_ID" DISTRO="$DISTRO" awk -F '\t' "$AWK_LIB"'
      BEGIN { init(); ns = ENVIRON["ID"]; distro = ENVIRON["DISTRO"] }
      $0 == "" { next }
      {
        if (NF != 5 || bad($1) || bad($2) || bad($3) || bad($4) || bad($5)) { unparsed("rpm", $0); next }
        if ($2 != "(none)" && $2 !~ /^[0-9]+$/) { unparsed("rpm", $0); next }
        v = $3 "-" $4
        q = ""
        if ($5 != "(none)") q = "arch=" enc($5)
        if (distro != "") q = q (q != "" ? "&" : "") "distro=" enc(distro)
        if ($2 != "(none)") q = q (q != "" ? "&" : "") "epoch=" $2
        p = "pkg:rpm/" (ns != "" ? enc(ns) "/" : "") enc($1) "@" enc(v) (q != "" ? "?" q : "")
        pkg("rpm", $1, v, p)
      }')"
  else
    add_pkg_out "U {\"manager\":\"rpm\",\"line\":\"rpm -qa failed\"}"
    note "rpm -qa failed; package list is incomplete"
  fi
fi

APK_DB=/lib/apk/db/installed
if [ -e "$APK_DB" ]; then
  if [ -r "$APK_DB" ]; then
    APK_NS=${OS_ID:-alpine}
    add_pkg_out "$(ID="$APK_NS" DISTRO="$DISTRO" awk "$AWK_LIB"'
      function flush() {
        if (name == "" && ver == "") return
        if (bad(name) || bad(ver) || (arch != "" && bad(arch))) unparsed("apk", "P:" name " V:" ver " A:" arch)
        else {
          q = ""
          if (arch != "") q = "arch=" enc(arch)
          if (distro != "") q = q (q != "" ? "&" : "") "distro=" enc(distro)
          pkg("apk", name, ver, "pkg:apk/" enc(ns) "/" enc(name) "@" enc(ver) (q != "" ? "?" q : ""))
        }
        name = ""; ver = ""; arch = ""
      }
      BEGIN { init(); ns = ENVIRON["ID"]; distro = ENVIRON["DISTRO"] }
      /^P:/ { name = substr($0, 3) }
      /^V:/ { ver = substr($0, 3) }
      /^A:/ { arch = substr($0, 3) }
      /^$/ { flush() }
      END { flush() }' "$APK_DB")"
  else
    add_pkg_out "U {\"manager\":\"apk\",\"line\":\"apk database unreadable\"}"
    note "apk database unreadable; package list is incomplete"
  fi
fi

if [ -z "$PKG_OUT" ]; then
  note "no dpkg, rpm, or apk package database found"
fi

# ---------------------------------------------------------------- facts

FACTS=""
fact() {
  FACTS="${FACTS}$(jstr "$1"):$(jstr "$2")
"
}

SSHD=""
if have sshd; then
  SSHD=$(command -v sshd)
elif [ -x /usr/local/sbin/sshd ]; then
  # make install's default prefix; often not on a non-login root PATH.
  SSHD=/usr/local/sbin/sshd
fi
LDD_OUT=""
LDD_OK=0
if [ -n "$SSHD" ] && have ldd; then
  if LDD_OUT=$(ldd "$SSHD" 2>/dev/null) && [ -n "$LDD_OUT" ]; then
    LDD_OK=1
  else
    note "ldd on sshd failed"
  fi
fi

# ------------------------------------------- source-built sshd (no package)
#
# A make-install OpenSSH is in no package database, so the regreSSHion pack
# would only see "sshd runs, no package". For each sshd binary found (the one
# on PATH and /usr/local/sbin/sshd) that every package database present says
# it does not own, `sshd -V` is read and one entry is written:
#   manager binary, name openssh, purl pkg:generic/openssh@<ver>,
#   path <binary>, source binary_version.
# The importer gives it confidence medium: it can make a check true, never
# clear one (a banner can be spoofed; a patched build can keep its banner).
# Nothing is written when ownership cannot be decided (no package database,
# a missing query tool, or a query error), when the banner is not exactly
# OpenSSH_MAJOR.MINOR[pPATCH] followed by "," or the end of the line (a
# distributor suffix such as "OpenSSH_9.2p1 Debian-2" is not a source build),
# or when the binary is owned by a package.

# pkg_owner prints owned, unowned, or unknown for one path.
pkg_owner() {
  po_paths=$1
  if have readlink && po_r=$(readlink -f "$1" 2>/dev/null) && [ -n "$po_r" ] && [ "$po_r" != "$1" ]; then
    case $po_r in /*) ;; *) echo unknown; return ;; esac
    case $po_r in *[!A-Za-z0-9/._+-]*) echo unknown; return ;; esac
    po_paths="$po_paths
$po_r"
  fi
  # usrmerge: the database may list /sbin/x for /usr/sbin/x or the reverse.
  po_all=$(printf '%s\n' "$po_paths" | awk 'NF > 0 {
    print
    if ($0 ~ /^\/usr\/(s?bin|lib)\//) print substr($0, 5)
    else if ($0 ~ /^\/(s?bin|lib)\//) print "/usr" $0
  }' | sort -u)
  po_any=0
  if [ -e /var/lib/dpkg/status ]; then
    po_any=1
    have dpkg-query || { echo unknown; return; }
    for po_p in $po_all; do
      dpkg-query -S "$po_p" >/dev/null 2>&1
      case $? in 0) echo owned; return ;; 1) ;; *) echo unknown; return ;; esac
    done
  fi
  if [ -d /var/lib/rpm ] || [ -d /usr/lib/sysimage/rpm ]; then
    po_any=1
    have rpm || { echo unknown; return; }
    for po_p in $po_all; do
      if po_o=$(rpm -qf "$po_p" 2>&1); then echo owned; return; fi
      case $po_o in *"is not owned by any package"*|*"No such file or directory"*) ;; *) echo unknown; return ;; esac
    done
  fi
  if [ -e "$APK_DB" ]; then
    po_any=1
    have apk || { echo unknown; return; }
    for po_p in $po_all; do
      if po_o=$(apk info --who-owns "$po_p" 2>&1); then
        case $po_o in *"is owned by"*) echo owned; return ;; *) echo unknown; return ;; esac
      fi
      case $po_o in *"Could not find owner package"*) ;; *) echo unknown; return ;; esac
    done
  fi
  if [ "$po_any" = 0 ]; then echo unknown; else echo unowned; fi
}

# sshd_banner_version prints "V version" or "X reason" from `sshd -V`.
# sshd before 9.x rejects -V but still prints the banner with its usage.
sshd_banner_version() {
  "$1" -V </dev/null 2>&1 | awk '
    /^OpenSSH_/ {
      n++
      line = $0
      if (line ~ /^OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?,/ || line ~ /^OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?$/) {
        v = substr(line, 9); sub(/,.*$/, "", v)
        split(v, a, /[.p]/)
        if (length(a[1]) <= 3 && length(a[2]) <= 3 && length(a[3]) <= 3) ver = v
        else why = "version component too long"
      } else why = "not exactly OpenSSH_MAJOR.MINOR[pPATCH] (distributor suffix or other form)"
    }
    END {
      if (n == 0) print "X no OpenSSH_ banner"
      else if (n > 1) print "X more than one OpenSSH_ banner"
      else if (ver != "") print "V " ver
      else print "X " why
    }'
}

BIN_SEEN=""
BIN_VERS=""
for b in "$SSHD" /usr/local/sbin/sshd; do
  [ -n "$b" ] && [ -f "$b" ] && [ -x "$b" ] || continue
  case $b in /*) ;; *) continue ;; esac
  case " $BIN_SEEN " in *" $b "*) continue ;; esac
  BIN_SEEN="$BIN_SEEN $b"
  case $b in *[!A-Za-z0-9/._+-]*) note "sshd at an unusual path; binary version not read"; continue ;; esac
  own=$(pkg_owner "$b")
  case $own in
    owned) continue ;;
    unknown) note "$b: package ownership not determined; binary version not read"; continue ;;
  esac
  r=$(sshd_banner_version "$b")
  case $r in
    "V "*)
      v=${r#V }
      case " $BIN_VERS " in *" $v "*) note "$b: openssh $v already recorded from another binary"; continue ;; esac
      BIN_VERS="$BIN_VERS $v"
      add_pkg_out "$(B="$b" V="$v" awk "$AWK_LIB"'BEGIN { init(); binpkg("openssh", ENVIRON["V"], "pkg:generic/openssh@" ENVIRON["V"], ENVIRON["B"]) }')"
      note "$b is in no package database; openssh $v read from its sshd -V banner (binary version: affected-only evidence)"
      ;;
    *) note "$b is in no package database; sshd -V banner not used: ${r#X }" ;;
  esac
done

# libc.family: prefer the libc sshd is linked against; else the system's.
LIBC=""
if [ "$LDD_OK" = 1 ]; then
  g=0; m=0
  printf '%s\n' "$LDD_OUT" | grep -q 'libc\.so\.6' && g=1
  printf '%s\n' "$LDD_OUT" | grep -q 'ld-musl\|libc\.musl' && m=1
  if [ "$g" = 1 ] && [ "$m" = 0 ]; then LIBC=glibc; fi
  if [ "$m" = 1 ] && [ "$g" = 0 ]; then LIBC=musl; fi
else
  g=0; m=0
  if have getconf && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then g=1; fi
  for f in /lib/ld-musl-*.so.1; do [ -e "$f" ] && m=1; done
  if [ "$g" = 1 ] && [ "$m" = 0 ]; then LIBC=glibc; fi
  if [ "$m" = 1 ] && [ "$g" = 0 ]; then LIBC=musl; fi
fi
if [ -n "$LIBC" ]; then fact libc.family "$LIBC"; else note "libc family not determined"; fi

if [ "$LDD_OK" = 1 ]; then
  if printf '%s\n' "$LDD_OUT" | grep -q 'liblzma'; then
    fact process.sshd.links_liblzma true
  else
    fact process.sshd.links_liblzma false
  fi
fi

# Listening TCP sockets as "port<TAB>process" lines. An empty process means
# the owner could not be seen.
LISTEN=""
LISTEN_OK=0
if have ss && out=$(ss -ltnp 2>/dev/null); then
  LISTEN=$(printf '%s\n' "$out" | awk '
    $1 == "State" || $0 == "" { next }
    {
      port = ""; procs = ""
      for (i = 1; i <= NF; i++) {
        if (port == "" && $i ~ /:[0-9]+$/) { port = $i; sub(/^.*:/, "", port) }
        if ($i ~ /^users:/) procs = procs $i
      }
      if (port == "") next
      found = 0
      while (match(procs, /\("[^"]*"/)) {
        print port "\t" substr(procs, RSTART + 2, RLENGTH - 3)
        procs = substr(procs, RSTART + RLENGTH)
        found = 1
      }
      if (!found) print port "\t"
    }')
  RAW_N=$(printf '%s\n' "$out" | awk '$1 != "State" && NF > 0 { n++ } END { print n + 0 }')
  LISTEN_OK=1
  LISTEN_SRC="ss -ltnp"
elif [ -r /proc/net/tcp ]; then
  # inode<TAB>port for each socket in LISTEN state (0A).
  socks=$(awk '
    function hex(h,   i, n, c) {
      n = 0; h = toupper(h)
      for (i = 1; i <= length(h); i++) {
        c = index("0123456789ABCDEF", substr(h, i, 1))
        if (c == 0) return -1
        n = n * 16 + c - 1
      }
      return n
    }
    FNR == 1 { next }
    $4 == "0A" { p = $2; sub(/^.*:/, "", p); print $10 "\t" hex(p) }' /proc/net/tcp /proc/net/tcp6 2>/dev/null)
  # pid<TAB>inode for each socket fd this user can see.
  # shellcheck disable=SC2012
  owners=$(ls -l /proc/[0-9]*/fd 2>/dev/null | awk '
    /^\/proc\/[0-9]+\/fd:$/ { pid = $0; sub(/^\/proc\//, "", pid); sub(/\/fd:$/, "", pid); next }
    /socket:\[[0-9]+\]/ { s = $0; sub(/^.*socket:\[/, "", s); sub(/\].*$/, "", s); print pid "\t" s }')
  pids=$(printf '%s\n' "$owners" | awk -F '\t' 'NF == 2 { print $1 }' | sort -u)
  comms=""
  for pid in $pids; do
    c=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
    comms="${comms}${pid}	${c}
"
  done
  # Each section marker is on its own line even when a section is empty.
  LISTEN=$(printf 'C\n%s\nO\n%s\nS\n%s\n' "$comms" "$owners" "$socks" | awk -F '\t' '
    $0 == "C" || $0 == "O" || $0 == "S" { sec = $0; next }
    $0 == "" { next }
    sec == "C" { comm[$1] = $2; next }
    sec == "O" { if ($1 in comm) own[$2] = (own[$2] == "" ? "" : own[$2] "\n") comm[$1]; next }
    sec == "S" {
      if ($2 < 0) next
      if ($1 in own) { n = split(own[$1], a, "\n"); for (i = 1; i <= n; i++) print $2 "\t" a[i] }
      else print $2 "\t"
    }')
  RAW_N=$(printf '%s\n' "$socks" | awk 'NF > 0 { n++ } END { print n + 0 }')
  LISTEN_OK=1
  LISTEN_SRC="/proc/net/tcp"
else
  note "no ss and no /proc/net/tcp; listening sockets not observed"
fi
if [ "$LISTEN_OK" = 1 ]; then
  LISTEN=$(printf '%s\n' "$LISTEN" | awk 'NF > 0' | sort -u -t '	' -k1,1n -k2,2)
  # Sockets were seen but none parsed: the table is unobserved, not empty.
  if [ "${RAW_N:-0}" -gt 0 ] && [ -z "$LISTEN" ]; then
    LISTEN_OK=0
    note "listening sockets seen by $LISTEN_SRC but not parsed; not observed"
  else
    note "listening sockets from $LISTEN_SRC"
  fi
fi

UNATTRIBUTED=0
SSHD_LISTEN=0
PORT22_UNCLEAR=0
if [ "$LISTEN_OK" = 1 ] && [ -n "$LISTEN" ]; then
  eval "$(printf '%s\n' "$LISTEN" | awk -F '\t' '
    $2 == "" { un = 1; if ($1 == 22) p22 = 1; next }
    $2 ~ /^sshd/ { sl = 1; next }
    $1 == 22 { p22 = 1 }
    END { printf "UNATTRIBUTED=%d SSHD_LISTEN=%d PORT22_UNCLEAR=%d\n", un, sl, p22 }')"
fi
if [ "$SSHD_LISTEN" = 1 ]; then
  fact process.listening.sshd true
elif [ "$LISTEN_OK" = 1 ] && [ "$UNATTRIBUTED" = 0 ]; then
  fact process.listening.sshd false
else
  note "process.listening.sshd omitted: socket owners not fully visible (run as root)"
fi

# service.socket_activation.sshd: true if any activator is seen; false only
# when every activator checked is determinately absent and tcp/22 is not
# held by anything but sshd.
SA_POS=0
SA_UNK=0
SA_UNITS=""
SYSTEMD_UP=0
if [ -d /run/systemd/system ]; then SYSTEMD_UP=1; fi
if [ -r /proc/1/comm ] && [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ]; then SYSTEMD_UP=1; fi
if [ "$SYSTEMD_UP" = 1 ]; then
  if have systemctl; then
    for u in ssh.socket sshd.socket; do
      if ! st=$(systemctl show -p LoadState -p UnitFileState -p ActiveState "$u" 2>/dev/null); then
        SA_UNK=1
        continue
      fi
      cls=$(printf '%s\n' "$st" | awk -F= '
        { v[$1] = $2 }
        END {
          if (v["LoadState"] == "not-found" || v["LoadState"] == "masked") { print "neg"; exit }
          if (v["LoadState"] != "loaded") { print "unk"; exit }
          a = v["ActiveState"]; f = v["UnitFileState"]
          if (a == "active" || a == "activating" || a == "reloading") { print "pos"; exit }
          if (f ~ /^(enabled|enabled-runtime|linked|linked-runtime|alias|indirect|generated)$/) { print "pos"; exit }
          if (f == "disabled" && (a == "inactive" || a == "failed")) { print "neg"; exit }
          print "unk"
        }')
      case $cls in pos) SA_POS=1; SA_UNITS="$SA_UNITS $u" ;; neg) ;; *) SA_UNK=1 ;; esac
    done
  else
    SA_UNK=1
  fi
fi
if [ -e /etc/inetd.conf ]; then
  if [ -r /etc/inetd.conf ]; then
    if grep -v '^[[:space:]]*#' /etc/inetd.conf | grep -q 'sshd'; then SA_POS=1; fi
  else
    SA_UNK=1
  fi
fi
for f in /etc/xinetd.conf /etc/xinetd.d/*; do
  [ -e "$f" ] || continue
  if [ -r "$f" ]; then
    if grep -v '^[[:space:]]*#' "$f" | grep -q 'sshd'; then SA_POS=1; fi
  else
    SA_UNK=1
  fi
done
if [ "$SA_POS" = 1 ]; then
  fact service.socket_activation.sshd true
elif [ "$SA_UNK" = 0 ] && [ "$LISTEN_OK" = 1 ] && [ "$PORT22_UNCLEAR" = 0 ]; then
  fact service.socket_activation.sshd false
else
  note "service.socket_activation.sshd omitted: an activator or the owner of tcp/22 could not be ruled out"
fi

# config.sshd.LoginGraceTime: sshd -T, else /etc/ssh/sshd_config with
# Include. A key that is not written is omitted, never the default.
CFG_AWK='
{
  sub(/^[ \t]+/, "")
  if ($0 == "" || substr($0, 1, 1) == "#") next
  kw = $0; sub(/[ \t=].*$/, "", kw)
  rest = substr($0, length(kw) + 1); sub(/^[ \t]*=?[ \t]*/, "", rest)
  k = tolower(kw)
  if (k == "match") { print "M"; exit }
  if (k == "include") {
    n = split(rest, a, /[ \t]+/)
    for (i = 1; i <= n; i++) { gsub(/"/, "", a[i]); if (a[i] != "" && substr(a[i], 1, 1) != "#") print "I " a[i] }
    next
  }
  if (k == "logingracetime") { v = rest; sub(/[ \t].*$/, "", v); gsub(/"/, "", v); print "L " v; exit }
}'

# cfg_file prints "L value", "M" (Match reached first), "B" (unreadable), or "N".
# It runs in a command substitution, so its variables do not leak.
cfg_file() {
  if [ "$2" -gt 16 ]; then echo B; return; fi
  if [ ! -r "$1" ]; then echo B; return; fi
  toks=$(awk "$CFG_AWK" "$1" 2>/dev/null) || { echo B; return; }
  IFS='
'
  set -f
  for t in $toks; do
    case $t in
      "L "*) echo "$t"; return ;;
      M) echo M; return ;;
      "I "*)
        pat=${t#I }
        case $pat in /*) ;; *) pat=/etc/ssh/$pat ;; esac
        set +f
        for f in $pat; do
          [ -e "$f" ] || continue
          r=$(cfg_file "$f" $(($2 + 1)))
          case $r in N) ;; *) echo "$r"; return ;; esac
        done
        set -f
        ;;
    esac
  done
  echo N
}

SSHD_T=""
SSHD_T_OK=0
if [ -n "$SSHD" ] && SSHD_T=$("$SSHD" -T 2>/dev/null) && [ -n "$SSHD_T" ]; then
  SSHD_T_OK=1
fi

LGT=""
if [ "$SSHD_T_OK" = 1 ]; then
  LGT=$(printf '%s\n' "$SSHD_T" | awk '$1 == "logingracetime" { print $2; exit }')
  [ -n "$LGT" ] && note "LoginGraceTime from sshd -T"
fi
if [ -z "$LGT" ] && [ -e /etc/ssh/sshd_config ]; then
  r=$(cfg_file /etc/ssh/sshd_config 0)
  case $r in
    "L "*) LGT=${r#L }; note "LoginGraceTime from /etc/ssh/sshd_config and its Include files" ;;
    B) note "LoginGraceTime omitted: an sshd config file was unreadable" ;;
    M) note "LoginGraceTime omitted: not set before the first Match block" ;;
    *) note "LoginGraceTime omitted: not set in sshd_config; the default is not assumed" ;;
  esac
fi
case $LGT in
  "") ;;
  *[!0-9smhdwSMHDW]*) note "LoginGraceTime value not recognized; omitted" ;;
  *) fact config.sshd.LoginGraceTime "$LGT" ;;
esac

# config.sshd.Port: every TCP port sshd accepts connections on, written as
# decimal ports in strictly ascending order joined by commas with no spaces
# (22, or 22,2222). The base set is sshd -T (every "port" line and the port
# of every "listenaddress" line), else sshd_config and its Include files up to
# the first Match: Port lines, plus the port of a ListenAddress that names
# one. Ports sshd is seen listening on and the ports of an active or enabled
# ssh.socket/sshd.socket are added. With no base set, a ListenAddress without
# a port and no Port line (the default would apply), or any value that does
# not parse, the fact is omitted. 22 is never assumed.

# lport prints the port of a ListenAddress value, "" when it has none, or
# BAD. Forms: host, host:port, a.b.c.d:port, [v6], [v6]:port, bare v6.
LADDR_AWK='
function lport(v,   p, n, t) {
  sub(/^[ \t]+/, "", v); sub(/[ \t].*$/, "", v); gsub(/"/, "", v)
  if (v ~ /^\[[^]]*\]:[0-9]+$/) { p = v; sub(/^.*\]:/, "", p); return p }
  if (v ~ /^\[[^]]*\]$/) return ""
  t = v; n = gsub(/:/, ":", t)
  if (n == 1 && v ~ /^[^:[]+:[0-9]+$/) { p = v; sub(/^.*:/, "", p); return p }
  if (n == 0 && v != "" && v !~ /[][]/) return ""
  if (n >= 2 && v !~ /[][]/) return ""
  return "BAD"
}'

PCFG_AWK="$LADDR_AWK"'
{
  sub(/^[ \t]+/, "")
  if ($0 == "" || substr($0, 1, 1) == "#") next
  kw = $0; sub(/[ \t=].*$/, "", kw)
  rest = substr($0, length(kw) + 1); sub(/^[ \t]*=?[ \t]*/, "", rest)
  k = tolower(kw)
  if (k == "match") { print "M"; exit }
  if (k == "include") {
    n = split(rest, a, /[ \t]+/)
    for (i = 1; i <= n; i++) { gsub(/"/, "", a[i]); if (a[i] != "" && substr(a[i], 1, 1) != "#") print "I " a[i] }
    next
  }
  if (k == "port") { v = rest; sub(/[ \t].*$/, "", v); gsub(/"/, "", v); print "Q " v; next }
  if (k == "listenaddress") {
    p = lport(rest)
    if (p == "") print "A"; else if (p == "BAD") print "X"; else print "L " p
  }
}'

# cfg_ports prints one token per line: "Q port" (Port line), "L port"
# (ListenAddress with a port), "A" (ListenAddress without one), "X"
# (unparsed ListenAddress), then "B" (unreadable or too deep) or "E" (done;
# a Match block ends the global section). It runs in a command
# substitution, so its variables do not leak.
cfg_ports() {
  if [ "$2" -gt 16 ]; then echo B; return; fi
  if [ ! -r "$1" ]; then echo B; return; fi
  toks=$(awk "$PCFG_AWK" "$1" 2>/dev/null) || { echo B; return; }
  IFS='
'
  set -f
  for t in $toks; do
    case $t in
      "Q "*|"L "*|A|X) echo "$t" ;;
      M) echo M; return ;;
      "I "*)
        pat=${t#I }
        case $pat in /*) ;; *) pat=/etc/ssh/$pat ;; esac
        set +f
        for f in $pat; do
          [ -e "$f" ] || continue
          r=$(cfg_ports "$f" $(($2 + 1)))
          printf '%s\n' "$r" | grep -v '^E$'
          case $r in *B*|*M*) return ;; esac
        done
        set -f
        ;;
    esac
  done
  echo E
}

PORT_LIST=""
PORT_BAD=0
PORT_SRC=""
if [ "$SSHD_T_OK" = 1 ] && printf '%s\n' "$SSHD_T" | grep -q '^port '; then
  PORT_LIST=$(printf '%s\n' "$SSHD_T" | awk "$LADDR_AWK"'
    $1 == "port" { print $2; next }
    $1 == "listenaddress" { p = lport($2); print (p == "" ? "BAD" : p) }')
  PORT_SRC="sshd -T"
elif [ -e /etc/ssh/sshd_config ]; then
  r=$(cfg_ports /etc/ssh/sshd_config 0)
  if printf '%s\n' "$r" | grep -q '^B$'; then
    note "config.sshd.Port omitted: an sshd config file was unreadable"
    PORT_BAD=1
  elif printf '%s\n' "$r" | grep -q '^X$'; then
    note "config.sshd.Port omitted: a ListenAddress value was not parsed"
    PORT_BAD=1
  elif printf '%s\n' "$r" | grep -q '^A$' && ! printf '%s\n' "$r" | grep -q '^Q '; then
    note "config.sshd.Port omitted: a ListenAddress has no port and no Port line is written; the default is not assumed"
    PORT_BAD=1
  else
    PORT_LIST=$(printf '%s\n' "$r" | sed -n 's/^[QL] //p')
    PORT_SRC="/etc/ssh/sshd_config and its Include files"
  fi
fi
if [ -n "$PORT_LIST" ] && [ "$PORT_BAD" = 0 ]; then
  # Ports a running sshd holds (command-line -p, or a config sshd -T did not
  # read) and ports a systemd socket unit holds for sshd.
  if [ "$LISTEN_OK" = 1 ] && [ -n "$LISTEN" ]; then
    PORT_LIST="$PORT_LIST
$(printf '%s\n' "$LISTEN" | awk -F '\t' '$2 ~ /^sshd/ { print $1 }')"
  fi
  for u in $SA_UNITS; do
    if ! lst=$(systemctl show -p Listen "$u" 2>/dev/null); then
      PORT_BAD=1
      note "config.sshd.Port omitted: could not read Listen of $u"
      continue
    fi
    PORT_LIST="$PORT_LIST
$(printf '%s\n' "$lst" | awk "$LADDR_AWK"'
      {
        sub(/^Listen=/, "")
        n = split($0, w, /[ \t]+/)
        for (i = 1; i <= n; i++) {
          if (w[i] == "" || w[i] ~ /^\(.*\)$/) continue
          if (w[i] ~ /^\//) continue
          if (w[i] ~ /^[0-9]+$/) { print w[i]; continue }
          p = lport(w[i]); print (p == "" ? "BAD" : p)
        }
      }')"
  done
fi
if [ -n "$PORT_LIST" ] && [ "$PORT_BAD" = 0 ]; then
  PORTS=$(printf '%s\n' "$PORT_LIST" | awk '
    NF == 0 { next }
    $0 !~ /^[0-9]+$/ || length($0) > 5 || $0 + 0 < 1 || $0 + 0 > 65535 { bad = 1; next }
    { print $0 + 0 }
    END { if (bad) print "BAD" }' | sort -un)
  case $PORTS in
    *BAD*|"") note "config.sshd.Port omitted: a port value was not a number in 1-65535" ;;
    *)
      PORTS=$(printf '%s\n' "$PORTS" | awk 'NF > 0 { if (n++) printf ","; printf "%s", $0 }')
      fact config.sshd.Port "$PORTS"
      note "config.sshd.Port from $PORT_SRC, listening sshd sockets, and sshd socket units"
      ;;
  esac
elif [ "$PORT_BAD" = 0 ]; then
  note "config.sshd.Port omitted: no sshd -T port lines and no Port or ListenAddress port in sshd_config"
fi

# ---------------------------------------------------------------- output

join_lines() {
  awk 'NF > 0 { if (n++) printf ","; printf "%s", $0 }'
}

{
  printf '{"schema":"verdict.collect-host/v1","collector":"collect-host.sh"'
  printf ',"hostname":%s' "$(jstr "$HOSTNAME_V")"
  printf ',"collected_at":%s' "$(jstr "$COLLECTED_AT")"
  printf ',"os":{'
  sep=""
  if [ -n "$OS_ID" ]; then printf '"id":%s' "$(jstr "$OS_ID")"; sep=","; fi
  if [ -n "$OS_VERSION_ID" ]; then printf '%s"version_id":%s' "$sep" "$(jstr "$OS_VERSION_ID")"; fi
  printf '}'
  printf ',"packages":['
  printf '%s' "$PKG_OUT" | sed -n 's/^P //p' | join_lines
  printf '],"unparsed":['
  printf '%s' "$PKG_OUT" | sed -n 's/^U //p' | join_lines
  printf '],"facts":{'
  printf '%s' "$FACTS" | join_lines
  printf '}'
  if [ "$LISTEN_OK" = 1 ]; then
    printf ',"listening":['
    printf '%s\n' "$LISTEN" | awk -F '\t' "$AWK_LIB"'
      BEGIN { init() }
      NF == 0 || $1 !~ /^[0-9]+$/ { next }
      {
        if (n++) printf ","
        printf "{\"port\":%d,\"proto\":\"tcp\"", $1
        if ($2 != "") printf ",\"process\":\"%s\"", esc($2)
        printf "}"
      }'
    printf ']'
  fi
  printf ',"notes":['
  printf '%s' "$NOTES" | while IFS= read -r n; do
    [ -n "$n" ] && jstr "$n" && printf '\n'
  done | join_lines
  printf ']}\n'
}
