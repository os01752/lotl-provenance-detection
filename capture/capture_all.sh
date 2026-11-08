#!/bin/bash
# capture_all.sh - collect the expanded IT 7178 dataset in one run.
#   24 benign administrative activities (12 are "hard negatives" that use the
#      same binaries as the attacks: crontab, chmod, curl, base64, python, sh)
#   17 emulated Living-off-the-Land techniques mapped to MITRE ATT&CK
# Every emulation is harmless: payloads only run id/whoami/uname/hostname,
# files live in /tmp or $HOME and are deleted, and the user's crontab and
# ~/.bashrc are backed up first and restored at the end.
#
# usage (inside the VM, from ~/lotl):  ./capture_all.sh
set -u
cd "$(dirname "$0")"
mkdir -p captures
sudo -v || exit 1                                    # cache sudo for ausearch
sudo auditctl -l | grep -q lotl_exec || { echo "audit rule lotl_exec not loaded"; exit 1; }

# --- safety backups --------------------------------------------------------
crontab -l > "$HOME/.lotl_crontab.bak" 2>/dev/null || : > "$HOME/.lotl_crontab.bak"
cp "$HOME/.bashrc" "$HOME/.lotl_bashrc.bak"
restore() {
  if [ -s "$HOME/.lotl_crontab.bak" ]; then crontab "$HOME/.lotl_crontab.bak"; else crontab -r 2>/dev/null; fi
  cp "$HOME/.lotl_bashrc.bak" "$HOME/.bashrc"
  rm -f "$HOME/.lotl_crontab.bak" "$HOME/.lotl_bashrc.bak"
  echo "[restore] crontab and ~/.bashrc restored"
}
trap restore EXIT

# run <label>  (command is read from the heredoc that follows)
# Note: ausearch reads events from stdin whenever stdin is not a terminal, so
# --input-logs is required to make it read the audit log inside a script.
run() {
  local label=$1 cmd start
  cmd=$(cat)
  start=$(date +%H:%M:%S); sleep 1
  bash -c "$cmd" </dev/null >/dev/null 2>&1
  sleep 1
  sudo ausearch --input-logs -k lotl_exec -ts "$start" --raw > "captures/$label.log" 2>/dev/null </dev/null
  printf '%-45s %3s execs\n' "$label" "$(grep -c '^type=SYSCALL' "captures/$label.log")"
  sleep 1
}

echo "== benign administration =="
run benign_disk_usage <<'CMD'
df -h; du -sh /var/log 2>/dev/null; free -m
CMD
run benign_proc_monitor <<'CMD'
top -bn1 | head -15; ps -eo pid,comm,%cpu --sort=-%cpu | head
CMD
run benign_service_status <<'CMD'
systemctl status ssh --no-pager | head -5; systemctl list-units --type=service --no-pager | head
CMD
run benign_log_grep <<'CMD'
grep -i error /var/log/syslog 2>/dev/null | tail -5; journalctl -p err -n 10 --no-pager
CMD
run benign_find_logs <<'CMD'
find /var/log -name '*.log' -mtime -1 2>/dev/null | head
CMD
run benign_backup_tar <<'CMD'
tar -czf /tmp/etc_backup.tar.gz /etc/hostname /etc/hosts 2>/dev/null; ls -lh /tmp/etc_backup.tar.gz; rm -f /tmp/etc_backup.tar.gz
CMD
run benign_pkg_policy <<'CMD'
apt-cache policy openssh-server | head -5; dpkg -s coreutils | head -3
CMD
run benign_net_diag <<'CMD'
ping -c 1 127.0.0.1; ss -s; ip route
CMD
run benign_user_audit <<'CMD'
last -n 5; lastlog 2>/dev/null | head -5; getent group sudo
CMD
run benign_file_perms <<'CMD'
ls -la /etc/ssh/ | head; stat /etc/passwd; chmod 644 ~/.profile
CMD
run benign_archive_logs <<'CMD'
cp /etc/hostname ~/h.txt; gzip -f ~/h.txt; gunzip -f ~/h.txt.gz; rm -f ~/h.txt
CMD
run benign_uptime_report <<'CMD'
uptime; who; hostnamectl 2>/dev/null | head -5
CMD

echo "== benign hard negatives (same tools as the attacks) =="
run benign_hard_crontab_list <<'CMD'
crontab -l 2>/dev/null; cat /etc/crontab
CMD
run benign_hard_chmod_script <<'CMD'
printf '#!/bin/sh\necho report\n' > ~/report.sh; chmod 755 ~/report.sh; ~/report.sh; rm -f ~/report.sh
CMD
run benign_hard_curl_download <<'CMD'
curl -s file:///etc/os-release -o ~/os-release.txt; head -3 ~/os-release.txt; rm -f ~/os-release.txt
CMD
run benign_hard_base64_encode <<'CMD'
base64 /etc/hostname; echo 'config backup' | base64
CMD
run benign_hard_base64_decode_file <<'CMD'
echo aGVsbG8K | base64 -d > ~/decoded.txt; cat ~/decoded.txt; rm -f ~/decoded.txt
CMD
run benign_hard_python_script <<'CMD'
python3 -c 'import platform; print(platform.platform())'; python3 -c 'print(sum(range(10)))'
CMD
run benign_hard_python_subprocess <<'CMD'
python3 -c 'import subprocess; print(subprocess.check_output(["uptime"]).decode())'
CMD
run benign_hard_sh_script <<'CMD'
printf 'df -h\nuptime\n' > ~/check.sh; sh ~/check.sh; rm -f ~/check.sh
CMD
run benign_hard_tmp_work <<'CMD'
mkdir -p /tmp/build; echo data > /tmp/build/out.txt; wc -l /tmp/build/out.txt; rm -rf /tmp/build
CMD
run benign_hard_nested_shell <<'CMD'
bash -c 'for i in 1 2 3; do echo $i; done'; sh -c 'date; uptime'
CMD
run benign_hard_sed_awk <<'CMD'
awk -F: '$3>=1000{print $1}' /etc/passwd; sed -n '1,3p' /etc/hosts
CMD
run benign_hard_hidden_config_read <<'CMD'
head -3 ~/.profile; ls -la ~ | head
CMD

echo "== emulated LotL techniques (MITRE ATT&CK) =="
run lotl_T1140_b64decode_sh <<'CMD'
echo aWQ7d2hvYW1p | base64 --decode | sh
CMD
run lotl_T1027_hex_xxd_bash <<'CMD'
echo 69643b686f73746e616d65 | xxd -r -p | bash
CMD
run lotl_T1027_rev_bash <<'CMD'
echo 'imaohw;di' | rev | bash
CMD
run lotl_T1027_printf_octal_bash <<'CMD'
printf '\151\144\073\165\156\141\155\145' | bash
CMD
run lotl_T1140_openssl_b64_bash <<'CMD'
echo aWQ7d2hvYW1p | openssl base64 -d | bash
CMD
run lotl_T1140_b64_file_exec <<'CMD'
echo aWQ7d2hvYW1p > /tmp/.enc; base64 -d /tmp/.enc > /tmp/.s.sh; sh /tmp/.s.sh; rm -f /tmp/.enc /tmp/.s.sh
CMD
run lotl_T1105_curl_hidden_exec <<'CMD'
printf '#!/bin/sh\nid\n' > /tmp/stage_src; curl -s file:///tmp/stage_src -o /tmp/.update.sh; chmod +x /tmp/.update.sh; /tmp/.update.sh; rm -f /tmp/stage_src /tmp/.update.sh
CMD
run lotl_T1105_python_download_exec <<'CMD'
printf 'id\n' > /tmp/stage_py; python3 -c "import urllib.request as u; open('/tmp/.py_upd','wb').write(u.urlopen('file:///tmp/stage_py').read())"; sh /tmp/.py_upd; rm -f /tmp/stage_py /tmp/.py_upd
CMD
run lotl_T1059.006_python_os_system <<'CMD'
python3 -c 'import os; os.system("id; whoami")'
CMD
run lotl_T1059.006_python_subprocess_sh <<'CMD'
python3 -c 'import subprocess; subprocess.run(["/bin/sh","-c","uname -a; id"])'
CMD
run lotl_T1053.003_cron_install <<'CMD'
echo '*/5 * * * * /tmp/.update.sh' > /tmp/.cr; crontab /tmp/.cr; crontab -l; crontab -r; rm -f /tmp/.cr
CMD
run lotl_T1546.004_bashrc_persist <<'CMD'
echo '/tmp/.update.sh &' >> ~/.bashrc; tail -1 ~/.bashrc; cp ~/.lotl_bashrc.bak ~/.bashrc
CMD
run lotl_T1036.005_masquerade_kworker <<'CMD'
cp /bin/sh /tmp/.kworker; /tmp/.kworker -c 'id; hostname'; rm -f /tmp/.kworker
CMD
run lotl_T1070.003_history_clear <<'CMD'
unset HISTFILE; history -c; export HISTFILE=/dev/null; id
CMD
run lotl_T1082_discovery_script <<'CMD'
printf 'whoami\nid\nuname -a\nhostname\ncat /etc/passwd\nps aux\n' > /tmp/.recon.sh; sh /tmp/.recon.sh > /dev/null; rm -f /tmp/.recon.sh
CMD
run lotl_T1222.002_chmod_hidden_exec <<'CMD'
printf '#!/bin/sh\nid\n' > /tmp/.x; chmod 777 /tmp/.x; /tmp/.x; rm -f /tmp/.x
CMD
run lotl_T1564.001_hidden_dir_exec <<'CMD'
mkdir -p /tmp/.cache_x; cp /bin/ls /tmp/.cache_x/ls; /tmp/.cache_x/ls /etc > /dev/null; rm -rf /tmp/.cache_x
CMD

echo "== done: $(ls captures/*.log | wc -l) capture files in captures/ =="
