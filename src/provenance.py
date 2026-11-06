"""
provenance.py - Build process-provenance graphs from host execution telemetry
and extract behavioural features for Living-off-the-Land (LotL) detection.

Pipeline
    raw telemetry --> event table --> parent linking --> provenance graph
                  --> task subtree --> behavioural features --> score

Each process *execution* (one execve) is a node, so a process that replaces
its image (bash exec'ing its last command as `sh`) appears as a bash -> sh
"exec" edge instead of being merged into one node. A child process links to
the most recent execution of its parent PID ("fork" edge).

Input formats
    * Linux auditd (`ausearch --raw`)  -> parse_audit_log()
    * Windows Sysmon EID 1 (JSON)      -> added in sysmon.py (same event table)
"""
import math
import os
import re
from collections import Counter
from pathlib import Path

import networkx as nx
import pandas as pd

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------
SHELLS = {"bash", "sh", "dash", "zsh", "ksh"}
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php"}
DECODERS = {"base64", "xxd", "openssl", "rev", "base32", "uudecode"}
DOWNLOADERS = {"curl", "wget"}
TMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")
KTHREAD_NAMES = ("kworker", "kthreadd", "ksoftirqd", "migration", "kswapd", "rcu_")

# Trusted binaries commonly abused in LotL tradecraft (GTFOBins-style).
LOTL_BINARIES = SHELLS | INTERPRETERS | DECODERS | DOWNLOADERS | {
    "chmod", "crontab", "at", "systemctl", "nc", "ncat", "socat", "awk", "sed",
}

# --------------------------------------------------------------------------
# auditd parsing
# --------------------------------------------------------------------------
_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')


def _parse_kv(line: str) -> dict:
    """Keep raw tokens (quotes included) to tell quoted strings from hex."""
    return {m.group(1): m.group(2) for m in _KV.finditer(line)}


def _int(val, default=-1) -> int:
    """Numeric audit fields are never hex-encoded; strip quotes if present."""
    if val is None:
        return default
    try:
        return int(val.strip('"'))
    except ValueError:
        return default


def _decode_arg(val) -> str:
    """auditd quotes plain strings and hex-encodes (unquoted) any value that
    contains spaces, quotes or control characters."""
    if val is None:
        return ""
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    if re.fullmatch(r"[0-9A-Fa-f]+", val) and len(val) % 2 == 0:
        try:
            return bytes.fromhex(val).decode("utf-8", "replace").replace("\x00", " ")
        except ValueError:
            pass
    return val


def parse_audit_log(path) -> pd.DataFrame:
    """One row per *successful* execve: node, pid, ppid, comm, exe, argv,
    cmdline, ts. Failed execve calls (e.g. a shell trying each PATH entry)
    are dropped."""
    events = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        m = re.match(r"type=(\w+) msg=audit\(([\d.]+):(\d+)\):\s*(.*)", line)
        if not m:
            continue
        rtype, ts, serial, body = m.groups()
        ev = events.setdefault(serial, {"ts": float(ts), "node": int(serial)})
        kv = _parse_kv(body)
        if rtype == "SYSCALL":
            ev.update(
                pid=_int(kv.get("pid")),
                ppid=_int(kv.get("ppid")),
                comm=_decode_arg(kv.get("comm", "")),
                exe=_decode_arg(kv.get("exe", "")),
                uid=_decode_arg(kv.get("uid", "")),
                success=_decode_arg(kv.get("success", "")),
            )
        elif rtype == "EXECVE":
            argc = _int(kv.get("argc"), 0)
            ev["argv"] = [_decode_arg(kv.get(f"a{i}")) for i in range(argc)]
    rows = [e for e in events.values() if "pid" in e and e.get("success") == "yes"]
    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["node", "pid", "ppid", "comm", "exe", "argv", "cmdline", "ts"])
    df["argv"] = df.get("argv", pd.Series([None] * len(df))).apply(
        lambda a: a if isinstance(a, list) else [])
    df["cmdline"] = df["argv"].apply(" ".join)
    return df.sort_values(["ts", "node"]).reset_index(drop=True)


# --------------------------------------------------------------------------
# Provenance graph
# --------------------------------------------------------------------------
def link_parents(df: pd.DataFrame) -> pd.DataFrame:
    """Resolve each execution's parent execution.
    * same PID seen before  -> 'exec' edge (image replacement)
    * parent PID seen before -> 'fork' edge from its latest execution
    * otherwise              -> root (parent outside the capture window)"""
    df = df.sort_values(["ts", "node"]).reset_index(drop=True)
    latest, parents, kinds = {}, [], []
    for r in df.itertuples():
        if r.pid in latest:
            parents.append(latest[r.pid]); kinds.append("exec")
        elif r.ppid in latest:
            parents.append(latest[r.ppid]); kinds.append("fork")
        else:
            parents.append(None); kinds.append("root")
        latest[r.pid] = r.node
    df["parent_node"], df["edge_type"] = parents, kinds
    return df


def build_graph(df: pd.DataFrame) -> nx.DiGraph:
    """Nodes = executions; edges = parent execution -> child execution."""
    g = nx.DiGraph()
    for r in df.itertuples():
        g.add_node(r.node, comm=r.comm, exe=r.exe, cmdline=r.cmdline,
                   argv=r.argv, ts=r.ts, pid=r.pid)
    for r in df.itertuples():
        if r.parent_node is not None and not pd.isna(r.parent_node) and r.parent_node in g:
            g.add_edge(r.parent_node, r.node, kind=r.edge_type)
    return g


def _base(p: str) -> str:
    return os.path.basename(p or "")


def task_subtree(g: nx.DiGraph) -> nx.DiGraph:
    """Keep only the activity under test: the earliest `bash -c <task>`
    execution (launched by capture.sh) and all of its descendants. This drops
    the capture harness (sleep, date, sudo, ausearch, grep) and any unrelated
    system activity in the same time window. Falls back to the largest
    connected component when no task root is present."""
    roots = sorted(
        (n for n, a in g.nodes(data=True)
         if _base(a["argv"][0] if a["argv"] else "") in SHELLS
         and len(a["argv"]) >= 3 and a["argv"][1] == "-c"),
        key=lambda n: g.nodes[n]["ts"])
    if roots:
        keep = {roots[0]} | nx.descendants(g, roots[0])
    elif g.number_of_nodes():
        keep = max(nx.weakly_connected_components(g), key=len)
    else:
        keep = set()
    return g.subgraph(keep).copy()


def tree_layout(g: nx.DiGraph, x_gap: float = 1.0, y_gap: float = 1.0) -> dict:
    """Top-down hierarchical layout (no graphviz needed)."""
    roots = [n for n in g.nodes if g.in_degree(n) == 0] or list(g.nodes)[:1]
    pos, next_x = {}, [0.0]

    def place(n, depth):
        kids = sorted(g.successors(n), key=lambda k: g.nodes[k].get("ts", 0))
        if not kids:
            pos[n] = (next_x[0], -depth * y_gap)
            next_x[0] += x_gap
            return
        for k in kids:
            place(k, depth + 1)
        xs = [pos[k][0] for k in kids]
        pos[n] = ((min(xs) + max(xs)) / 2, -depth * y_gap)

    for r in sorted(roots, key=lambda k: g.nodes[k].get("ts", 0)):
        place(r, 0)
        next_x[0] += x_gap * 0.5
    return pos


# --------------------------------------------------------------------------
# Features
# --------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _depth(g: nx.DiGraph) -> int:
    best = 0
    for r in (n for n in g.nodes if g.in_degree(n) == 0):
        best = max([best] + list(nx.single_source_shortest_path_length(g, r).values()))
    return best


def _in_tmp(path: str) -> bool:
    return any(path.startswith(d) for d in TMP_DIRS)


def _hidden(path: str) -> bool:
    return any(part.startswith(".") and part not in (".", "..")
               for part in path.split("/")[:-1] + [_base(path)])


_ESC = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}")
_HEX = re.compile(r"(?<![\w/.-])[0-9a-fA-F]{16,}(?![\w/.-])")
_B64 = re.compile(r"(?<![\w/.~-])[A-Za-z0-9+/]{16,}={0,2}(?![\w/.-])")


def _looks_encoded(text: str) -> bool:
    """Escape sequences, long hex strings, or base64-like tokens. A base64
    token must not look like a file path and must mix upper/lower case with
    digits or base64 symbols."""
    if _ESC.search(text) or _HEX.search(text):
        return True
    for t in _B64.findall(text):
        if t.startswith("/") or t.count("/") > 1:
            continue
        if re.search(r"[a-z]", t) and re.search(r"[A-Z]", t) and re.search(r"[0-9+/=]", t):
            return True
    return False

# Each indicator is a binary behavioural signal derived from MITRE ATT&CK
# technique descriptions (fixed before evaluation).
INDICATORS = [
    "f_decode_to_shell",     # T1140/T1027: decoder output piped into a shell
    "f_pipe_to_shell",       # T1059.004: shell reading commands from stdin
    "f_obfuscated_cmd",      # T1027: escape sequences / long encoded tokens
    "f_exec_from_tmp",       # T1059/T1204: execution of a file in /tmp etc.
    "f_hidden_exec",         # T1564.001: execution from a hidden path
    "f_download_then_exec",  # T1105: downloaded file later executed
    "f_chmod_exec_tmp",      # T1222.002: exec bit set on a tmp/hidden file
    "f_persistence",         # T1053.003 / T1546.004: cron install, rc edit
    "f_interp_spawns_shell", # T1059.006: interpreter launches a shell
    "f_history_tamper",      # T1070.003: shell history clearing/disabling
    "f_masquerade",          # T1036.005: kernel-thread-like or dot names
]


def extract_features(g: nx.DiGraph) -> dict:
    nodes = [g.nodes[n] for n in g.nodes]
    comms = [_base(a["comm"]) for a in nodes]
    cmds = [a["cmdline"] for a in nodes]
    joined = "\n".join(cmds)
    low = joined.lower()

    def kids(n):
        return [g.nodes[k] for k in g.successors(n)]

    # --- structural ---------------------------------------------------------
    shell_spawns_shell = sum(
        1 for u, v in g.edges
        if _base(g.nodes[u]["comm"]) in SHELLS and _base(g.nodes[v]["comm"]) in SHELLS)
    exec_edges = sum(1 for *_, k in g.edges(data="kind") if k == "exec")
    max_fanout = max((g.out_degree(n) for n in g.nodes), default=0)

    # --- indicators ---------------------------------------------------------
    stdin_shell = lambda a: _base(a["comm"]) in SHELLS and len(a["argv"]) == 1
    decoding = lambda a: (_base(a["comm"]) in DECODERS and (
        _base(a["comm"]) == "rev" or re.search(r"(^|\s)(-d|--decode|-r|-D)(\s|$)", a["cmdline"])))

    f_pipe_to_shell = int(any(stdin_shell(a) for a in nodes)
                          or bool(re.search(r"\|\s*(ba|da|z)?sh\s*($|;)", low, re.M)))
    f_decode_to_shell = int(any(
        any(decoding(k) for k in kids(n)) and (
            any(stdin_shell(k) for k in kids(n))
            or re.search(r"\|\s*(ba|da|z)?sh\s*($|;)", g.nodes[n]["cmdline"].lower()))
        for n in g.nodes))
    f_obfuscated_cmd = int(any(_looks_encoded(c) for c in cmds))

    # What was actually executed: the resolved image, argv[0], and - when the
    # image is a shell/interpreter (incl. a shebang script, which auditd logs
    # as "/bin/sh /path/script") - the script path passed as argv[1].
    exe_paths = [p for a in nodes for p in (a["exe"], a["argv"][0] if a["argv"] else "") if p]
    script_args = [a["argv"][1] for a in nodes
                   if a["argv"] and _base(a["argv"][0]).rstrip("0123456789.") in SHELLS | {"python", "perl", "ruby", "node", "php"}
                   and len(a["argv"]) >= 2 and not a["argv"][1].startswith("-")]
    f_exec_from_tmp = int(any(_in_tmp(p) for p in exe_paths + script_args))
    f_hidden_exec = int(any(_hidden(p) and p.startswith("/") for p in exe_paths + script_args))

    dl_targets = set(re.findall(r"(?:-o|-O|--output)\s+(\S+)", joined))
    dl_targets |= set(re.findall(r"open\(['\"]([^'\"]+)['\"]\s*,\s*['\"]wb", joined))
    downloaded = any(c in DOWNLOADERS for c in comms) or "urlopen" in low
    f_download_then_exec = int(downloaded and any(
        t == p for t in dl_targets for p in exe_paths + script_args))

    f_chmod_exec_tmp = int(any(
        _base(a["comm"]) == "chmod" and re.search(r"\+x|\b[0-7]?[1357][0-7]{2}\b", a["cmdline"])
        and any(_in_tmp(x) or _hidden(x) for x in a["argv"][2:])
        for a in nodes))

    f_persistence = int(
        any(_base(a["comm"]) == "crontab" and len(a["argv"]) >= 2
            and a["argv"][1] not in ("-l", "-r") for a in nodes)
        or any(_base(a["comm"]) == "systemctl" and "enable" in a["argv"] for a in nodes)
        or any(_base(a["comm"]) == "at" for a in nodes)
        or bool(re.search(r">>?\s*\S*\.(bashrc|profile|bash_profile|zshrc)\b", low))
        or bool(re.search(r">>?\s*/etc/cron", low)))

    f_interp_spawns_shell = int(any(
        _base(g.nodes[u]["comm"]).rstrip("0123456789.") in {"python", "perl", "ruby", "node", "php"}
        and _base(g.nodes[v]["comm"]) in SHELLS for u, v in g.edges))

    f_history_tamper = int(bool(re.search(
        r"history\s+-c|unset\s+histfile|histfile=/dev/null|histsize=0|\.bash_history", low)))

    f_masquerade = int(any(_base(p).lstrip(".").startswith(KTHREAD_NAMES) for p in exe_paths))

    ind = dict(
        f_decode_to_shell=f_decode_to_shell, f_pipe_to_shell=f_pipe_to_shell,
        f_obfuscated_cmd=f_obfuscated_cmd, f_exec_from_tmp=f_exec_from_tmp,
        f_hidden_exec=f_hidden_exec, f_download_then_exec=f_download_then_exec,
        f_chmod_exec_tmp=f_chmod_exec_tmp, f_persistence=f_persistence,
        f_interp_spawns_shell=f_interp_spawns_shell, f_history_tamper=f_history_tamper,
        f_masquerade=f_masquerade)

    lotl_used = sorted(set(comms) & LOTL_BINARIES)
    ents = [shannon_entropy(c) for c in cmds] or [0.0]
    return dict(
        n_processes=len(nodes),
        chain_depth=_depth(g),
        max_fanout=max_fanout,
        exec_edges=exec_edges,
        shell_spawns_shell=shell_spawns_shell,
        n_lotl_binaries=len(lotl_used),
        lotl_binaries=",".join(lotl_used),
        max_cmdline_len=max((len(c) for c in cmds), default=0),
        mean_cmdline_entropy=round(sum(ents) / len(ents), 3),
        max_cmdline_entropy=round(max(ents), 3),
        **ind,
        behaviour_score=sum(ind.values()),
    )


# --------------------------------------------------------------------------
# Dataset loading and baseline
# --------------------------------------------------------------------------
LEGACY_TECHNIQUE = {
    "lotl_obfusc_shell": "T1059.004",
    "lotl_download_exec": "T1105",
    "lotl_cron_persist": "T1053.003",
}


def technique_of(name: str) -> str:
    m = re.match(r"lotl_(T\d{4}(?:\.\d{3})?)_", name)
    return m.group(1) if m else LEGACY_TECHNIQUE.get(name, "benign" if name.startswith("benign") else "?")


def load_all(capture_dir):
    """Parse every *.log in capture_dir -> (features_df, graphs, frames)."""
    feats, graphs, frames = [], {}, {}
    for p in sorted(Path(capture_dir).glob("*.log")):
        name = p.stem
        df = link_parents(parse_audit_log(p))
        g = task_subtree(build_graph(df))
        f = extract_features(g)
        f.update(capture=name,
                 label="malicious" if name.startswith("lotl_") else "benign",
                 technique=technique_of(name),
                 hard_negative=int(name.startswith("benign_hard_")))
        feats.append(f)
        graphs[name] = g
        frames[name] = df[df.node.isin(g.nodes)].reset_index(drop=True)
    front = ["capture", "label", "technique", "hard_negative"]
    out = pd.DataFrame(feats)
    return out[front + [c for c in out.columns if c not in front]], graphs, frames


def baseline_name_detector(g: nx.DiGraph) -> int:
    """Signature-style baseline: flag if ANY LotL-capable binary other than the
    task's own launching shell appears (1 = flagged)."""
    comms = [_base(g.nodes[n]["comm"]) for n in g.nodes if g.in_degree(n) > 0]
    return int(bool(set(comms) & (LOTL_BINARIES - {"sed", "awk"})))
