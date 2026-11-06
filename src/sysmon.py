"""
sysmon.py - Windows adapter: Sysmon Event ID 1 (process creation) -> the same
provenance-graph representation used for Linux auditd (provenance.py).

Nodes are executions keyed by ProcessGuid; an edge links ParentProcessGuid ->
ProcessGuid. The unit of analysis is an *execution unit*: a process whose
parent started before the capture window, plus all of its descendants. The
pre-existing parent is attached as a context node (it is what makes
"WmiPrvSE -> net user /add" or "dllhost -> cmd" suspicious), but parents are
never shared between units, so long-lived system processes (services.exe,
svchost.exe) do not merge unrelated activity into one graph.

Windows indicators mirror the Linux indicator concepts (encoding, script
schemes, remote payloads, proxy execution, unusual parentage, user-writable
paths, persistence, account manipulation, injection), using ATT&CK vocabulary.
NOTE: these were written after inspecting the 13 pilot datasets, so the pilot
is a feasibility check; the final evaluation freezes them and uses unseen
OTRF datasets as a held-out set.
"""
import json
import re
from pathlib import Path

import networkx as nx
import pandas as pd

from provenance import _looks_encoded, tree_layout  # noqa: F401  (shared helpers)

PROXY_LOLBINS = {"mshta.exe", "regsvr32.exe", "rundll32.exe", "installutil.exe", "cmstp.exe",
                 "hh.exe", "mavinject.exe", "msiexec.exe", "odbcconf.exe", "regasm.exe",
                 "regsvcs.exe", "wmic.exe", "bitsadmin.exe", "certutil.exe", "msbuild.exe"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
ADMIN_TOOLS = {"net.exe", "net1.exe", "whoami.exe", "schtasks.exe", "reg.exe", "sc.exe"}
# Signature-style baseline: any well-known LOLBin / LOLScript name
WIN_LOLBIN_NAMES = PROXY_LOLBINS | SCRIPT_HOSTS | SHELLS | ADMIN_TOOLS
# Parents that should not normally spawn a shell or admin tool
UNUSUAL_SHELL_PARENTS = {"dllhost.exe", "wmiprvse.exe", "mshta.exe", "regsvr32.exe", "hh.exe",
                         "rundll32.exe", "wscript.exe", "cscript.exe", "installutil.exe",
                         "mavinject.exe", "winword.exe", "excel.exe", "outlook.exe",
                         "w3wp.exe", "sqlservr.exe"}
USER_WRITABLE = re.compile(r"\\(programdata|appdata|temp|users\\public)\\", re.I)

WIN_INDICATORS = [
    "w_encoded_cmd",          # T1027/T1140  -enc / encoded tokens
    "w_script_scheme",        # T1059.005/.007 javascript:/vbscript:/script:
    "w_remote_payload",       # T1105  URL in a command line
    "w_proxy_exec",           # T1218  signed-binary proxy execution
    "w_lolbin_spawns_child",  # T1218  proxy LOLBin / script host with a child
    "w_unusual_shell_parent", # T1047/T1548.002  shell/admin tool from odd parent
    "w_user_writable_exec",   # T1204  image/payload in ProgramData/AppData/Temp
    "w_persistence",          # T1053.005/T1547  schtasks /create, Run keys, sc create
    "w_account_manip",        # T1136  net user /add, localgroup admins /add
    "w_injection",            # T1055  mavinject /INJECTRUNNING
]


def _b(path) -> str:
    return str(path or "").replace("/", "\\").split("\\")[-1].lower()


def parse_sysmon(path) -> pd.DataFrame:
    """Sysmon EID 1 events from an OTRF JSON-lines file."""
    rows = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("EventID") != 1 or "sysmon" not in str(e.get("Channel", e.get("SourceName", ""))).lower():
            continue
        rows.append(dict(node=e.get("ProcessGuid"), parent_guid=e.get("ParentProcessGuid"),
                         pid=e.get("ProcessId"), ppid=e.get("ParentProcessId"),
                         comm=_b(e.get("Image")), exe=e.get("Image", ""),
                         cmdline=str(e.get("CommandLine") or ""), parent_comm=_b(e.get("ParentImage")),
                         parent_cmdline=str(e.get("ParentCommandLine") or ""),
                         host=e.get("Hostname", ""), user=e.get("User", ""),
                         ts=str(e.get("UtcTime", e.get("@timestamp", "")))))
    return pd.DataFrame(rows).sort_values("ts").reset_index(drop=True) if rows else pd.DataFrame()


def execution_units(df: pd.DataFrame) -> list:
    """One graph per root execution (parent outside the window) + descendants,
    with the pre-existing parent attached as a context node."""
    full = nx.DiGraph()
    for r in df.itertuples():
        full.add_node(r.node, comm=r.comm, exe=r.exe, cmdline=r.cmdline, ts=r.ts, context=False)
    for r in df.itertuples():
        if r.parent_guid in full:
            full.add_edge(r.parent_guid, r.node)
    units = []
    for r in df.itertuples():
        if r.parent_guid in full:
            continue
        keep = {r.node} | nx.descendants(full, r.node)
        g = full.subgraph(keep).copy()
        ctx = f"ctx:{r.node}"
        g.add_node(ctx, comm=r.parent_comm, exe="", cmdline=r.parent_cmdline, ts=r.ts, context=True)
        g.add_edge(ctx, r.node)
        units.append(g)
    return units


def win_features(g: nx.DiGraph) -> dict:
    procs = [g.nodes[n] for n in g.nodes if not g.nodes[n]["context"]]
    cmds = [a["cmdline"] for a in procs]
    low = "\n".join(cmds).lower()
    children = lambda n: [g.nodes[k]["comm"] for k in g.successors(n) if g.nodes[k]["comm"] != "conhost.exe"]

    ind = dict(
        w_encoded_cmd=int(bool(re.search(r"\s-e(nc|ncodedcommand)?\s", low)) or any(_looks_encoded(c) for c in cmds)),
        w_script_scheme=int(bool(re.search(r"(javascript|vbscript|script):|getobject\(", low))),
        w_remote_payload=int(bool(re.search(r"https?://|/i:http|\\\\\\\\[0-9a-z.]+\\\\", low))),
        w_proxy_exec=int(any(a["comm"] in PROXY_LOLBINS for a in procs)),
        w_lolbin_spawns_child=int(any(g.nodes[n]["comm"] in PROXY_LOLBINS | SCRIPT_HOSTS and children(n)
                                      for n in g.nodes)),
        w_unusual_shell_parent=int(any(g.nodes[v]["comm"] in SHELLS | ADMIN_TOOLS
                                       and g.nodes[u]["comm"] in UNUSUAL_SHELL_PARENTS
                                       for u, v in g.edges)),
        w_user_writable_exec=int(any(USER_WRITABLE.search(a["exe"] or "") or USER_WRITABLE.search(a["cmdline"])
                                     for a in procs)),
        w_persistence=int(bool(re.search(r"schtasks(\.exe)?\"?\s+/create|currentversion\\run|sc(\.exe)?\s+create", low))),
        w_account_manip=int(bool(re.search(r"net1?(\.exe)?\s+(user|localgroup)\b.*\s/add", low))),
        w_injection=int(bool(re.search(r"mavinject.*/injectrunning", low))),
    )
    depth = max(nx.single_source_shortest_path_length(g, n).__len__() for n in g.nodes if g.in_degree(n) == 0) - 1
    return dict(n_processes=len(procs), chain_depth=depth, **ind, behaviour_score=sum(ind.values()))


def win_baseline(g: nx.DiGraph) -> int:
    """Signature-style baseline: flag if any well-known LOLBin name appears."""
    return int(any(g.nodes[n]["comm"] in WIN_LOLBIN_NAMES for n in g.nodes if not g.nodes[n]["context"]))


# Ground truth for the pilot: a unit is malicious if any execution matches the
# technique documented for that OTRF dataset. Units containing only
# side-effects of the payload (the UWP Calculator activation) are excluded.
PILOT_LABELS = {
    "cmd_bitsadmin_download_psh_script":   ("T1197",     r"bitsadmin.*/transfer"),
    "cmd_mshta_javascript_getobject_sct":  ("T1218.005", r"mshta"),
    "cmd_mshta_vbscript_execute_psh":      ("T1218.005", r"mshta"),
    "covenant_installutil":                ("T1218.004", r"installutil"),
    "empire_launcher_sct_regsvr32":        ("T1218.010", r"regsvr32"),
    "empire_schtasks_creation_standard_user": ("T1053.005", r"schtasks.*/create"),
    "empire_wmic_add_user_backdoor":       ("T1047",     r"wmic.*process call create|net1? +user .*/add"),
    "psh_cmstp_execution_bypassuac":       ("T1218.003", r"cmstp|3e5fc7f9-9a51-4367-9063-a120244fbec7"),
    "psh_hh_local_html_payload":           ("T1218.001", r"hh\.exe"),
    "psh_mavinject_dll_notepad":           ("T1055.001", r"mavinject|notepad\.exe"),
    "psh_mshta_html_application_execution": ("T1218.005", r"mshta"),
    "schtask_create":                      ("T1053.005", r"schtasks.*/create"),
    "wmic_remote_xsl_jscript":             ("T1220",     r"wmic.*/format"),
}
SIDE_EFFECT = re.compile(r"windowscalculator", re.I)


def load_otrf(json_dir) -> tuple:
    """Every execution unit in every pilot dataset -> (features_df, graphs)."""
    feats, graphs = [], {}
    for f in sorted(Path(json_dir).glob("*/*.json")):
        ds = f.parent.name
        technique, pattern = PILOT_LABELS.get(ds, ("?", r"$^"))
        df = parse_sysmon(f)
        if df.empty:
            continue
        for i, g in enumerate(execution_units(df)):
            text = "\n".join(g.nodes[n]["cmdline"] + " " + g.nodes[n]["exe"] for n in g.nodes
                             if not g.nodes[n]["context"]).lower()
            if SIDE_EFFECT.search(text):
                continue
            mal = bool(re.search(pattern, text))
            name = f"{ds}#{i}"
            row = win_features(g)
            root = next(n for n in g.nodes if g.nodes[n]["context"])
            row.update(unit=name, dataset=ds, label="malicious" if mal else "benign",
                       technique=technique if mal else "benign",
                       chain=" > ".join([g.nodes[root]["comm"]] + [g.nodes[k]["comm"] for k in nx.dfs_preorder_nodes(g, root)][1:5]),
                       baseline=win_baseline(g))
            feats.append(row)
            graphs[name] = g
    out = pd.DataFrame(feats)
    front = ["unit", "dataset", "label", "technique", "chain"]
    return out[front + [c for c in out.columns if c not in front]], graphs
