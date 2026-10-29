# Captured telemetry

Put your 8 raw `ausearch --raw` log files here, one per activity:

Benign (legitimate admin):
- benign_sysinfo.log
- benign_pkgquery.log
- benign_useradmin.log
- benign_logcheck.log
- benign_netcheck.log

Malicious (emulated LotL, MITRE ATT&CK):
- lotl_obfusc_shell.log      (T1059.004)
- lotl_download_exec.log     (T1105)
- lotl_cron_persist.log      (T1053.003)

Copy them from the VM with:
  scp -r olaolus@192.168.64.2:~/lotl/captures/*.log .
