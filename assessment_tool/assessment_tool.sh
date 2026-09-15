#!/usr/bin/env bash
#
# ============================================================================
#  BOILERPLATE : Linux Security Assessment Tool  (IS2083 Lab 1)
# ============================================================================
#  This is a boilerplate you can use to create your own script. Copy it,
#  rename it, and fill in each TODO section by section, following the handout.
#  Do not skip ahead: build and test one section at a time.
#
#  Target: a Debian based Linux VM (Ubuntu or Kali). Run from a terminal.
#  On a Red Hat based system, replace the Debian commands with equivalents
#  (apt -> dnf, ufw -> firewalld, /var/log/auth.log -> /var/log/secure).
# ============================================================================

set -u   # catch unset variables. We avoid 'set -e' so one failed check
         # does not stop the whole assessment.

# --- Section 2: Name the tool ------------------------------------------------
TOOL_NAME="IronTest"

# --- Section 3: Startup dialog -----------------------------------------------
zenity --info --width=360 --title="IronTest" \
	--text="IronTest has started." \
	2>/dev/null || echo "[IronTest] started"

sudo -v

# --- Section 4: Report creation (file manipulation) --------------------------
WORKDIR="$HOME/IronTest_reports"
mkdir -p "$WORKDIR"
REPORT="$WORKDIR/report_$(date +%F_%H%M%S).txt"
touch "$REPORT"
log() { echo "$*" | tee -a "$REPORT"; }
section() { log ""; log "===== $* ====="; }
log "IronTest security report"
log "Generated : $(date)"
log "Host : $(hostname)"
log "Run by : $(whoami)"

# --- Section 5: System administration ----------------------------------------
section "System administration"
log "Operating system : $(uname -srm)"
log "Uptime : $(uptime -p)"
log "Disk usage on / :"
df -h / | tee -a "$REPORT"
log "Accounts with root privileges (UID 0):"
awk -F: '$3==0 {print " " $1}' /etc/passwd | tee -a "$REPORT"
log "Members of the sudo group:"
getent group sudo | cut -d: -f4 | tr ',' '\n' | sed 's/^/ /' | tee -a "$REPORT"
UPGRADES=$(dnf list --upgradable 2>/dev/null | tail -n +2 | wc -l)
log "Packages that can be upgraded: $UPGRADES"

# --- Section 6: Process control ----------------------------------------------
section "Process control"
log "Total running processes: $(ps -e --no-headers | wc -l)"
log "Top 5 processes by CPU:"
ps -eo pid,comm,%cpu --sort=-%cpu | head -n 6 | tee -a "$REPORT"
log "Top 5 processes by memory:"
ps -eo pid,comm,%mem --sort=-%mem | head -n 6 | tee -a "$REPORT"
log "Network services that are listening:"
ss -tuln | tee -a "$REPORT"
log "Starting a temporary background watcher..."
sleep 120 &
WATCHER_PID=$!
log " watcher started as PID $WATCHER_PID"
kill "$WATCHER_PID" 2>/dev/null && log " watcher (PID $WATCHER_PID) stopped"

# --- Section 7: File security audit ------------------------------------------
section "File and permission audit"
WORLD_WRITABLE=$(find /home -xdev -type f -perm -0002 2>/dev/null | wc -l)
log "World writable files under /home: $WORLD_WRITABLE"
find /home -xdev -type f -perm -0002 2>/dev/null | sed 's/^/ /' | tee -a "$REPORT"
log "SUID programs under /usr/bin and /usr/sbin:"
find /usr/bin /usr/sbin -xdev -type f -perm -4000 2>/dev/null | sed 's/^/ /' | tee -a "$REPORT"
log "Permissions on sensitive files:"
ls -l /etc/passwd /etc/shadow | tee -a "$REPORT"

# --- Section 8: Security hardening --------------------------------------------
section "Hardening actions"
if command -v firewalld >/dev/null; then
	sudo systemctl enable --now firewalld >/dev/null 2>&1
	sudo firewall-cmd --set-default-zone=drop >/dev/null 2>&1
	FW_ENABLED=1
	log "Firewall (firewalld) enabled with default deny incoming."
	sudo firewall-cmd --state | tee -a "$REPORT"
#	sudo firewalld status verbose | tee -a "$REPORT"
else
	FW_ENABLED=0
	log "firewalld is not installed. Install: sudo dnf install firewalld"
fi

FAILED=$(sudo grep "Failed password" /var/log/secure 2>/dev/null | wc -l)
log "Failed SSH login attempts on record: $FAILED"

EMPTY=$(sudo awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | wc -l)
log "Accounts with an EMPTY password: $EMPTY (should be 0)"

# --- Section 9: Security score -----------------------------------------------
section "Security score"
SCORE=100
[ "$UPGRADES" -gt 0 ] && SCORE=$((SCORE - 10))
[ "$WORLD_WRITABLE" -gt 0 ] && SCORE=$((SCORE - 15))
[ "$FAILED" -gt 20 ] && SCORE=$((SCORE - 10))
[ "$EMPTY" -gt 0 ] && SCORE=$((SCORE - 30))
[ "$FW_ENABLED" -eq 0 ] && SCORE=$((SCORE - 20))
[ "$SCORE" -lt 0 ] && SCORE=0
if [ "$SCORE" -ge 90 ]; then RATING="STRONG"
elif [ "$SCORE" -ge 70 ]; then RATING="MODERATE"
else RATING="NEEDS WORK"
fi
log "Security score: $SCORE / 100 ($RATING)"

# --- Section 10: Completion dialog -------------------------------------------
# TODO: chmod 600 the report, then show a zenity box that says
#       "<TOOL_NAME> has completed", the security score, and the report path.
section "Finishing up"
chmod 600 "$REPORT"
log "Report locked to owner only (chmod 600)."
log "Report saved to: $REPORT"
zenity --info --width=420 --title="IronTest" \
--text="$IronTest has completed."$'\n'"Security score: $SCORE / 100
($RATING)" \
2>/dev/null || echo "[IronTest] completed. Score: $SCORE/100"

# --- Section 11: GitHub (do this in the terminal, not in the script) ---------
#   git init
#   git add .
#   git commit -m "Version 1.0 of my Linux Security Assessment Tool"
#   git branch -M main
#   git remote add origin <your repo URL>
#   git push -u origin main
