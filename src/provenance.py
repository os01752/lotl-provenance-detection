"""
provenance.py - Parse Linux auditd execve logs into process-provenance graphs
and extract behavioural features for Living-off-the-Land (LotL) detection.

Input : raw `ausearch --raw` output, one file per labelled capture.
Output: a networkx DiGraph per capture (parent pid -> child pid) and a
        per-capture feature vector.
"""
import math
import re
from collections import Counter
from pathlib import Path

import networkx as nx
import pandas as pd

# Processes that belong to the capture harness itself, not the task under test.
HARNESS_COMMS = {"capture.sh", "ausearch", "date", "sleep", "sudo"}

# Trusted binaries commonly abused in LotL tradecraft (GTFOBins / LOLBAS style).
LOTL_BINARIES = {
    "bash", "sh", "dash", "zsh", "curl", "wget", "base64", "chmod",
    "crontab", "python3", "perl", "nc", "openssl", "xxd", "awk", "sed",
}
SHELLS = {"bash", "sh", "dash", "zsh"}

_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')


def _parse_kv(line: str) -> dict:
    """Keep the raw token (quotes included) so we can tell quoted strings
    from hex-encoded ones later."""
    out = {}
    for m in _KV.finditer(line):
        out[m.group(1)] = m.group(2)
    return out


def _int(val, default=-1) -> int:
    """Numeric audit fields are never hex-encoded; strip quotes if present."""
    if val is None:
        return default
    try:
        return int(val.strip('"'))
    except ValueError:
        return default


def _decode_arg(val: str) -> str:
    """Audit quotes plain strings and hex-encodes (unquoted) any value
    containing spaces, quotes or control characters."""
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
    """Return one row per execve event: pid, ppid, comm, exe, argv, cmdline, ts."""
    events = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        m = re.match(r"type=(\w+) msg=audit\(([\d.]+):(\d+)\):\s*(.*)", line)
        if not m:
            continue
        rtype, ts, serial, body = m.groups()
        ev = events.setdefault(serial, {"ts": float(ts), "serial": int(serial)})
        if rtype == "SYSCALL":
            kv = _parse_kv(body)
            ev.update(
                pid=_int(kv.get("pid")),
                ppid=_int(kv.get("ppid")),
                comm=_decode_arg(kv.get("comm", "")),
                exe=_decode_arg(kv.get("exe", "")),
                uid=_decode_arg(kv.get("uid", "")),
                success=_decode_arg(kv.get("success", "")),
            )
        elif rtype == "EXECVE":
            kv = _parse_kv(body)
            argc = _int(kv.get("argc"), 0)
            argv = [_decode_arg(kv.get(f"a{i}")) for i in range(argc)]
            ev["argv"] = argv
            ev["cmdline"] = " ".join(argv)
    rows = [e for e in events.values() if "pid" in e]
    df = pd.DataFrame(rows).sort_values(["ts", "serial"]).reset_index(drop=True)
    if "cmdline" not in df:
        df["cmdline"] = ""
    df["cmdline"] = df["cmdline"].fillna("")
    df["argv"] = df["argv"].apply(lambda a: a if isinstance(a, list) else [])
    return df


def filter_harness(df: pd.DataFrame) -> pd.DataFrame:
    """Drop the capture harness so graphs show only the task under test."""
    keep = ~df["comm"].isin(HARNESS_COMMS)
    # The outer `bash -c "<task>"` launched by capture.sh is the task root; keep it.
    return df[keep].reset_index(drop=True)


def build_graph(df: pd.DataFrame) -> nx.DiGraph:
    """Nodes = processes (pid), edges = parent -> child."""
    g = nx.DiGraph()
    for _, r in df.iterrows():
        g.add_node(r.pid, comm=r.comm, exe=r.exe, cmdline=r.cmdline, ts=r.ts)
    pids = set(df.pid)
    for _, r in df.iterrows():
        if r.ppid in pids and r.ppid != r.pid:
            g.add_edge(r.ppid, r.pid)
        else:
            # Parent outside the captured window (e.g. the interactive shell).
            root = f"ext:{r.ppid}"
            g.add_node(root, comm="(external parent)", exe="", cmdline="", ts=r.ts)
            g.add_edge(root, r.pid)
    return g


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _depth(g: nx.DiGraph) -> int:
    roots = [n for n in g.nodes if g.in_degree(n) == 0]
    best = 0
    for r in roots:
        for _, d in nx.single_source_shortest_path_length(g, r).items():
            best = max(best, d)
    return best


def extract_features(g: nx.DiGraph, df: pd.DataFrame) -> dict:
    cmds = df["cmdline"].tolist()
    comms = df["comm"].tolist()
    joined = "\n".join(cmds).lower()

    # Structural
    n_proc = len(df)
    depth = _depth(g)
    shell_spawns_shell = sum(
        1 for u, v in g.edges
        if g.nodes[u].get("comm") in SHELLS and g.nodes[v].get("comm") in SHELLS
    )

    # Command-line
    max_len = max((len(c) for c in cmds), default=0)
    mean_entropy = sum(shannon_entropy(c) for c in cmds) / max(n_proc, 1)
    max_entropy = max((shannon_entropy(c) for c in cmds), default=0.0)

    # Behavioural indicators (each is a binary flag)
    f_b64_to_shell = int(bool(re.search(r"base64\s+(-d|--decode)", joined))
                         and any(c in SHELLS for c in comms))
    f_hidden_path = int(bool(re.search(r"/(tmp|dev/shm|var/tmp)/\.", joined)))
    f_chmod_exec = int("chmod" in comms and bool(re.search(r"chmod\s+\+x|chmod\s+[0-7]*7[0-7]*", joined)))
    f_download = int(any(c in {"curl", "wget"} for c in comms))
    f_persistence = int("crontab" in comms or "systemctl" in comms or "at" in comms)
    f_tmp_exec = int(bool(re.search(r"(^|\s)(sh|bash)\s+-c\s+['\"]?(cat|\.|/tmp)", joined))
                     or bool(re.search(r"\s/tmp/\S+\s*$", joined, re.M)))

    lotl_binaries_used = sorted(set(comms) & LOTL_BINARIES)

    # Simple transparent behavioural score (0-6): sum of indicators.
    behaviour_score = (f_b64_to_shell + f_hidden_path + f_chmod_exec
                       + f_persistence + shell_spawns_shell * 0 + f_tmp_exec
                       + int(f_download and (f_chmod_exec or f_hidden_path)))

    return dict(
        n_processes=n_proc,
        chain_depth=depth,
        shell_spawns_shell=shell_spawns_shell,
        n_lotl_binaries=len(lotl_binaries_used),
        lotl_binaries=",".join(lotl_binaries_used),
        max_cmdline_len=max_len,
        mean_cmdline_entropy=round(mean_entropy, 3),
        max_cmdline_entropy=round(max_entropy, 3),
        f_b64_to_shell=f_b64_to_shell,
        f_hidden_path=f_hidden_path,
        f_chmod_exec=f_chmod_exec,
        f_download=f_download,
        f_persistence=f_persistence,
        f_tmp_exec=f_tmp_exec,
        behaviour_score=behaviour_score,
    )


def load_all(capture_dir) -> tuple[pd.DataFrame, dict, dict]:
    """Parse every *.log in capture_dir. Returns (features_df, graphs, frames)."""
    feats, graphs, frames = [], {}, {}
    for p in sorted(Path(capture_dir).glob("*.log")):
        name = p.stem
        label = "malicious" if name.startswith("lotl_") else "benign"
        df = filter_harness(parse_audit_log(p))
        g = build_graph(df)
        f = extract_features(g, df)
        f.update(capture=name, label=label)
        feats.append(f)
        graphs[name] = g
        frames[name] = df
    cols = ["capture", "label"] + [c for c in feats[0] if c not in ("capture", "label")]
    return pd.DataFrame(feats)[cols], graphs, frames


def baseline_name_detector(df: pd.DataFrame) -> int:
    """Naive baseline: flag if ANY LotL binary appears. 1 = flagged."""
    return int(bool(set(df["comm"]) & (LOTL_BINARIES - {"sed", "awk"})))
