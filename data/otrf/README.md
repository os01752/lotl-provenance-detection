# OTRF Security Datasets — Windows pilot subset

13 atomic datasets from the Open Threat Research Forge (OTRF) Security Datasets project
(https://github.com/OTRF/Security-Datasets), redistributed unmodified for reproducibility of the
Windows pilot. Each zip holds the host event log (JSON lines) recorded while one ATT&CK technique
was executed on a lab domain; the notebook uses the Sysmon Event ID 1 (process creation) records.

| dataset | ATT&CK |
|---|---|
| cmd_bitsadmin_download_psh_script | T1197 |
| cmd_mshta_javascript_getobject_sct | T1218.005 |
| cmd_mshta_vbscript_execute_psh | T1218.005 |
| covenant_installutil | T1218.004 |
| empire_launcher_sct_regsvr32 | T1218.010 |
| empire_schtasks_creation_standard_user | T1053.005 |
| empire_wmic_add_user_backdoor | T1047 / T1136 |
| psh_cmstp_execution_bypassuac | T1218.003 / T1548.002 |
| psh_hh_local_html_payload | T1218.001 |
| psh_mavinject_dll_notepad | T1055.001 |
| psh_mshta_html_application_execution | T1218.005 |
| schtask_create | T1053.005 |
| wmic_remote_xsl_jscript | T1220 |

Source: Rodriguez, R. and Rodriguez, J., OTRF Security Datasets. Licensed by the original authors;
see the upstream repository for terms.
