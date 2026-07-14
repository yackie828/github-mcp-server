#!/usr/bin/env bash
set -u

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
WHITE='\033[1;37m'
RESET='\033[0m'
BOLD='\033[1m'

REPORT_FILE="/root/elite_audit_$(date +%Y%m%d_%H%M%S).txt"
KNOWN_SUID_LIST=(
  /usr/bin/chage /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/mount
  /usr/bin/newgrp /usr/bin/passwd /usr/bin/su /usr/bin/sudo /usr/bin/umount
  /usr/lib/polkit-1/polkit-agent-helper-1
)

strip_color() { sed -r 's/\x1B\[[0-9;]*m//g'; }
log_line() { printf '%b\n' "$*" | tee -a "$REPORT_FILE"; }
section() {
  log_line "\n${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  log_line "${MAGENTA}${BOLD}► $1${RESET}"
  log_line "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}
ok() { log_line "  ${GREEN}[✔]${RESET} $1"; }
warn() { log_line "  ${YELLOW}[⚠]${RESET} $1"; }
bad() { log_line "  ${RED}[✘]${RESET} $1"; }
info() { log_line "  ${CYAN}[i]${RESET} $1"; }
flag() { log_line "  ${RED}${BOLD}[🚩 FLAG]${RESET} $1"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }
print_kv() { info "$(printf '%-18s %s' "$1:" "$2")"; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    printf '%b\n' "${RED}[✘] This audit must run as root.${RESET}" >&2
    exit 1
  fi
}

banner() {
  log_line "${CYAN}${BOLD}"
  log_line "╔════════════════════════════════════════════════════════════╗"
  log_line "║             ELITE ENDEAVOUROS SECURITY AUDIT              ║"
  log_line "║        Home Defensive Hardening & Vulnerability Scan      ║"
  log_line "╚════════════════════════════════════════════════════════════╝"
  log_line "${RESET}"
}

setup_report() {
  : >"$REPORT_FILE"
  print_kv "Report File" "$REPORT_FILE"
}

system_information_module() {
  section "1) System Information Module"
  local os_name="unknown"
  if [[ -f /etc/os-release ]]; then
    os_name=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release)
  fi
  local cpu="unknown"
  if [[ -f /proc/cpuinfo ]]; then
    cpu=$(awk -F: '/model name/{gsub(/^ +/,"",$2);print $2;exit}' /proc/cpuinfo)
  fi
  local product="unknown"
  if [[ -r /sys/devices/virtual/dmi/id/product_name ]]; then
    product=$(cat /sys/devices/virtual/dmi/id/product_name)
  fi

  print_kv "Hostname" "$(hostname 2>/dev/null || echo unknown)"
  print_kv "OS" "$os_name"
  print_kv "Kernel" "$(uname -r 2>/dev/null || echo unknown)"
  print_kv "Architecture" "$(uname -m 2>/dev/null || echo unknown)"
  print_kv "Uptime" "$(uptime -p 2>/dev/null || echo unknown)"
  print_kv "CPU" "$cpu"
  print_kv "Hardware" "$product"
  print_kv "Memory" "$(free -h 2>/dev/null | awk '/^Mem:/{print $2" total / "$3" used / "$4" free"}' || echo unknown)"
  print_kv "Root Disk" "$(df -h / 2>/dev/null | awk 'NR==2{print $2" total / "$3" used / "$4" free"}' || echo unknown)"
}

kernel_vulnerability_check() {
  section "2) Kernel Vulnerability Check"

  local les=""
  for candidate in \
    /usr/share/linux-exploit-suggester/linux-exploit-suggester.sh \
    /usr/local/bin/linux-exploit-suggester.sh \
    /usr/bin/linux-exploit-suggester.sh \
    /usr/bin/les.sh; do
    if [[ -x "$candidate" || -f "$candidate" ]]; then
      les="$candidate"
      break
    fi
  done

  if [[ -n "$les" ]]; then
    ok "linux-exploit-suggester detected at $les"
    local cve_matches
    cve_matches=$(bash "$les" 2>/dev/null | grep -E 'CVE-[0-9]{4}-[0-9]+' | head -n 25 || true)
    if [[ -n "$cve_matches" ]]; then
      warn "Potential kernel exploit matches detected (top 25 shown):"
      while IFS= read -r line; do
        warn "$line"
      done <<<"$cve_matches"
    else
      ok "No obvious kernel CVE suggestions returned by linux-exploit-suggester"
    fi
  else
    warn "linux-exploit-suggester not installed"
    info "Install on Arch/EndeavourOS: yay -S linux-exploit-suggester"
  fi

  declare -A sysctl_checks=(
    [kernel.randomize_va_space]=2
    [kernel.kptr_restrict]=2
    [kernel.dmesg_restrict]=1
    [kernel.unprivileged_bpf_disabled]=1
    [kernel.yama.ptrace_scope]=1
    [net.ipv4.conf.all.accept_redirects]=0
    [net.ipv4.conf.default.accept_redirects]=0
    [net.ipv4.conf.all.rp_filter]=1
    [net.ipv4.tcp_syncookies]=1
    [net.ipv6.conf.all.accept_redirects]=0
    [fs.protected_hardlinks]=1
    [fs.protected_symlinks]=1
  )

  for key in "${!sysctl_checks[@]}"; do
    local expected="${sysctl_checks[$key]}"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null || echo "missing")
    if [[ "$actual" == "$expected" ]]; then
      ok "$key = $actual"
    else
      bad "$key = $actual (expected $expected)"
    fi
  done
}

user_privilege_audit() {
  section "3) User & Privilege Audit"
  info "UID 0 accounts:"
  while IFS=: read -r user _ uid _ _ _ shell; do
    [[ "$uid" == "0" ]] || continue
    if [[ "$user" == "root" ]]; then
      ok "root account present with shell $shell"
    else
      flag "Unexpected UID 0 account: $user (shell: $shell)"
    fi
  done </etc/passwd

  info "Interactive shell users:"
  awk -F: '$7 ~ /(bash|zsh|fish|sh)$/ {print $1" -> "$7}' /etc/passwd 2>/dev/null | while IFS= read -r line; do
    info "$line"
  done

  if [[ -f /etc/sudoers ]]; then
    if have_cmd visudo && visudo -c >/dev/null 2>&1; then
      ok "sudoers syntax is valid"
    else
      bad "sudoers validation failed (visudo -c)"
    fi

    grep -R -h -E '^[^#].*(NOPASSWD|ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL)' /etc/sudoers /etc/sudoers.d 2>/dev/null | while IFS= read -r line; do
      warn "Potential broad sudo privilege: $line"
    done
  else
    warn "/etc/sudoers missing"
  fi

  info "Recent successful logins (last 10):"
  last -n 10 2>/dev/null | while IFS= read -r line; do
    info "$line"
  done

  info "Recent failed SSH logins (last 10):"
  journalctl -u sshd -n 300 --no-pager 2>/dev/null | grep -i 'Failed password' | tail -n 10 | while IFS= read -r line; do
    bad "$line"
  done
}

suid_sgid_binary_scan() {
  section "4) SUID/SGID Binary Scan"
  local suid_count=0
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    suid_count=$((suid_count + 1))
    local known=0
    for k in "${KNOWN_SUID_LIST[@]}"; do
      if [[ "$file" == "$k" ]]; then
        known=1
        break
      fi
    done
    if [[ "$known" -eq 1 ]]; then
      ok "Known SUID: $file"
    else
      flag "Unusual SUID binary: $file"
    fi
  done < <(find / -xdev -type f -perm -4000 2>/dev/null | sort)
  print_kv "Total SUID files" "$suid_count"

  local sgid_count=0
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    sgid_count=$((sgid_count + 1))
    warn "SGID file: $file"
  done < <(find / -xdev -type f -perm -2000 2>/dev/null | sort)
  print_kv "Total SGID files" "$sgid_count"
}

flag_secret_discovery() {
  section "5) Flag & Secret Discovery"

  info "CTF-style flag pattern scan"
  grep -R -n -I -E 'flag\{[^}]{1,200}\}|ctf\{[^}]{1,200}\}|FLAG\{[^}]{1,200}\}' \
    /root /home /opt /var/tmp /tmp 2>/dev/null | head -n 40 | while IFS= read -r line; do
    flag "$line"
  done

  info "Sensitive file discovery (.env, key material)"
  local perms=""
  find /root /home /etc /opt -xdev \( -name '.env' -o -name '*.pem' -o -name 'id_rsa' -o -name 'id_ed25519' \) 2>/dev/null | while IFS= read -r path; do
    flag "Sensitive file candidate: $path"
    perms=$(stat -c '%a' "$path" 2>/dev/null || echo "unknown")
    info "Permissions: $perms"
  done

  info "API/token keyword scan (redacted output)"
  local location=""
  grep -R -n -I -E '(api[_-]?key|secret|token|passwd|password|authorization)' \
    /root /home /etc /opt 2>/dev/null | head -n 60 | while IFS= read -r line; do
    location="${line%%:*}:${line#*:}"
    flag "Keyword match: ${location%%:*}:$(echo "${location#*:}" | sed 's/[[:alnum:]][[:alnum:]_\-]\{3,\}/[REDACTED]/g')"
  done
}

network_analysis() {
  section "6) Network Analysis"

  if have_cmd ss; then
    info "Listening sockets"
    ss -tulpn 2>/dev/null | sed -n '1,80p' | while IFS= read -r line; do
      if [[ "$line" == *LISTEN* || "$line" == *Netid* ]]; then
        warn "$line"
      fi
    done

    info "Established external connections"
    ss -tpn state established 2>/dev/null | sed -n '1,60p' | while IFS= read -r line; do
      info "$line"
    done
  else
    bad "ss command missing"
  fi

  info "Firewall configuration"
  if have_cmd nft; then
    nft list ruleset 2>/dev/null | sed -n '1,80p' | while IFS= read -r line; do info "$line"; done
  elif have_cmd iptables; then
    iptables -L -n -v --line-numbers 2>/dev/null | sed -n '1,80p' | while IFS= read -r line; do info "$line"; done
  else
    warn "No nftables/iptables command found"
  fi

  info "ARP/neighbor table"
  if have_cmd ip; then
    ip neigh show 2>/dev/null | while IFS= read -r line; do info "$line"; done
  fi

  info "Promiscuous interfaces"
  ip -details link show 2>/dev/null | awk '/^[0-9]+:/{iface=$2} /PROMISC/{print iface" "$0}' | while IFS= read -r line; do
    flag "Promiscuous mode detected: $line"
  done
}

process_cron_analysis() {
  section "7) Process & Cron Analysis"

  info "Top CPU processes"
  ps aux --sort=-%cpu 2>/dev/null | head -n 15 | while IFS= read -r line; do info "$line"; done

  info "Root-owned non-kernel processes"
  ps -eo user,pid,%cpu,%mem,comm,args --sort=-%cpu 2>/dev/null | awk '$1=="root"{print}' | head -n 40 | while IFS= read -r line; do
    warn "$line"
  done

  info "System cron directories"
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$d" ]] || continue
    find "$d" -maxdepth 1 -type f 2>/dev/null | while IFS= read -r file; do warn "Cron file: $file"; done
  done

  info "User crontabs"
  while IFS=: read -r user _ _ _ _ _ _; do
    crontab -u "$user" -l 2>/dev/null | sed "/^[[:space:]]*#/d;/^[[:space:]]*$/d" | while IFS= read -r line; do
      warn "Crontab [$user]: $line"
    done
  done </etc/passwd

  if have_cmd systemctl; then
    info "systemd timers"
    systemctl list-timers --all --no-pager 2>/dev/null | sed -n '1,50p' | while IFS= read -r line; do info "$line"; done
  fi
}

filesystem_integrity() {
  section "8) File System Integrity"

  info "World-writable files (local fs)"
  find / -xdev -type f -perm -0002 \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null | head -n 120 | while IFS= read -r file; do
    bad "World-writable file: $file"
  done

  info "Recently modified system files in /etc (7 days)"
  find /etc -type f -mtime -7 2>/dev/null | head -n 80 | while IFS= read -r file; do
    warn "Recent /etc change: $file"
  done

  info "Suspicious hidden files"
  find /root /home -xdev -type f -name '.*' 2>/dev/null | grep -Ev '/\.(bashrc|bash_history|profile|zshrc|gitconfig)$' | head -n 120 | while IFS= read -r file; do
    warn "Hidden file: $file"
  done

  info "Orphaned files (no user/group)"
  find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 120 | while IFS= read -r file; do
    bad "Orphaned ownership: $file"
  done
}

package_service_audit() {
  section "9) Package & Service Audit"
  if have_cmd pacman; then
    info "Pending package updates"
    pacman -Qu 2>/dev/null | head -n 80 | while IFS= read -r line; do warn "Update: $line"; done
  else
    warn "pacman not found"
  fi

  if have_cmd systemctl; then
    info "Enabled services"
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | sed -n '1,80p' | while IFS= read -r line; do info "$line"; done

    info "Failed services"
    systemctl --failed --no-pager 2>/dev/null | sed -n '1,80p' | while IFS= read -r line; do
      if [[ "$line" == *failed* ]]; then
        bad "$line"
      elif [[ -n "$line" ]]; then
        info "$line"
      fi
    done
  fi
}

ssh_hardening_check() {
  section "10) SSH Hardening Check"
  local cfg="/etc/ssh/sshd_config"
  if [[ ! -f "$cfg" ]]; then
    warn "sshd_config not found (OpenSSH server may be absent)"
    return
  fi

  declare -A checks=(
    [PermitRootLogin]=no
    [PasswordAuthentication]=no
    [PermitEmptyPasswords]=no
    [PubkeyAuthentication]=yes
    [X11Forwarding]=no
    [MaxAuthTries]=4
    [ClientAliveInterval]=300
  )

  for key in "${!checks[@]}"; do
    local expected="${checks[$key]}"
    local actual
    actual=$(awk -v k="$key" 'tolower($1)==tolower(k){print $2}' "$cfg" | tail -n1)
    if [[ -z "$actual" ]]; then
      warn "$key not explicitly set"
    elif [[ "${actual,,}" == "${expected,,}" ]]; then
      ok "$key=$actual"
    else
      bad "$key=$actual (recommended $expected)"
    fi
  done

  if have_cmd sshd; then
    if sshd -t >/dev/null 2>&1; then
      ok "sshd -t syntax check passed"
    else
      bad "sshd -t syntax check failed"
    fi
  fi
}

rootkit_backdoor_detection() {
  section "11) Rootkit & Backdoor Detection"

  if have_cmd rkhunter; then
    warn "Running rkhunter warning-only scan (can take time)"
    rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | tail -n 80 | while IFS= read -r line; do warn "$line"; done
  else
    warn "rkhunter not installed"
  fi

  if have_cmd chkrootkit; then
    warn "Running chkrootkit"
    chkrootkit 2>/dev/null | grep -E 'INFECTED|suspicious|Vulnerable' | while IFS= read -r line; do
      flag "$line"
    done
  else
    warn "chkrootkit not installed"
  fi

  info "Kernel modules with suspicious naming"
  lsmod 2>/dev/null | awk 'NR>1{print $1}' | grep -Ei '(rootkit|hide|keylog|backdoor|inject)' | while IFS= read -r line; do
    flag "Suspicious module name: $line"
  done

  info "Potential hidden process anomalies"
  ps -e -o pid= 2>/dev/null | sort -n > /tmp/elite_audit_ps_pids.$$
  ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n > /tmp/elite_audit_proc_pids.$$
  comm -13 /tmp/elite_audit_ps_pids.$$ /tmp/elite_audit_proc_pids.$$ | head -n 40 | while IFS= read -r pid; do
    [[ -n "$pid" ]] && flag "PID appears in /proc but not ps: $pid"
  done
  rm -f /tmp/elite_audit_ps_pids.$$ /tmp/elite_audit_proc_pids.$$
}

final_summary() {
  section "Audit Summary"
  ok "Audit complete"
  print_kv "Report" "$REPORT_FILE"
  info "Offline review: less $REPORT_FILE"
  cp "$REPORT_FILE" "${REPORT_FILE}.plain"
  strip_color <"$REPORT_FILE" >"${REPORT_FILE}.plain" || true
  info "Plain text copy: ${REPORT_FILE}.plain"
}

main() {
  require_root
  banner
  setup_report

  system_information_module
  kernel_vulnerability_check
  user_privilege_audit
  suid_sgid_binary_scan
  flag_secret_discovery
  network_analysis
  process_cron_analysis
  filesystem_integrity
  package_service_audit
  ssh_hardening_check
  rootkit_backdoor_detection
  final_summary
}

main "$@"
