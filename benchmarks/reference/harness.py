#!/usr/bin/env python3
"""Benchmark de referência harness, started by run.sh. Standard library only.

Every round restarts both servers, then runs every cell against both, in turns, with the order
swapped on odd rounds so that neither gets the quieter half of a round. All samples are kept:
nothing is dropped, and samples disturbed by other processes are flagged, not removed.
"""
import argparse
import csv
import json
import os
import platform
import resource
import shlex
import signal
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

LD = "simpleIOGenericIO"
REFS = {"scalar": f"{LD}/GGIO1.AnIn1.mag.f[MX]", "do": f"{LD}/GGIO1.AnIn1[MX]"}
PORTS = {"libiec61850": 11102, "openiec61850": 11104}
# Distinct cores of the 6 performance cores, away from CPU 0 (where WSL2 tends to land interrupts).
SERVER_CPUS = {4, 6}
CLIENT_CPUS = {8, 10}
HZ = os.sysconf("SC_CLK_TCK")
# Foreign use of the pinned CPUs, in cores, above which a sample is flagged as noisy.
NOISY_CORES = 0.10


def client_commands(port):
    host = "127.0.0.1"
    util = ["mms_utility", "-h", host, "-p", str(port)]
    return {
        "mms_utility_identify": util + ["-i"],
        "mms_utility_read": util + ["-a", LD, "-r", "GGIO1$MX$AnIn1$mag$f"],
        "client_example2_discovery": ["iec61850_client_example2", host, str(port)],
        "client_example4_dataset": ["iec61850_client_example4", host, str(port)],
    }


def pin(cpus):
    return lambda: os.sched_setaffinity(0, cpus)


def wait_listening(port):
    for _ in range(100):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    sys.exit(f"nothing listening on {port}")


def start_servers(args):
    peer = subprocess.Popen(
        [str(args.peer_bin / "server_example_basic_io"), str(PORTS["libiec61850"])],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=pin(SERVER_CPUS),
        cwd=args.out)
    # --period 100 matches the 10 Hz at which the example server's AnIn1 was measured to change.
    ours = subprocess.Popen(
        [str(args.server), "--scl", str(args.icd), "--port", str(PORTS["openiec61850"]),
         "--bind", "127.0.0.1", "--simulate", "--period", "100", "--max-associations", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=pin(SERVER_CPUS))
    for port in PORTS.values():
        wait_listening(port)
    return {"libiec61850": peer, "openiec61850": ours}


def stop_servers(servers):
    for p in servers.values():
        p.send_signal(signal.SIGTERM)
    for p in servers.values():
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()


def process_cpu_s(pid):
    with open(f"/proc/{pid}/stat", encoding="ascii") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / HZ


def process_threads(pid):
    return len(os.listdir(f"/proc/{pid}/task"))


def cpu_busy_s():
    """Busy seconds per CPU since boot, from /proc/stat."""
    busy = {}
    with open("/proc/stat", encoding="ascii") as f:
        for line in f:
            if line.startswith("cpu") and line[3].isdigit():
                name, *v = line.split()
                v = [int(x) for x in v[:8]]
                busy[int(name[3:])] = (sum(v) - v[3] - v[4]) / HZ
    return busy


class Interference:
    """What ran on the pinned CPUs and on the whole machine, besides the two measured processes."""

    def __init__(self):
        self.t0 = time.monotonic()
        self.busy0 = cpu_busy_s()

    def finish(self, own_cpu_s):
        wall = time.monotonic() - self.t0
        busy1 = cpu_busy_s()
        delta = {c: busy1[c] - self.busy0[c] for c in busy1}
        pinned = sum(delta[c] for c in SERVER_CPUS | CLIENT_CPUS)
        foreign_pinned = max(0.0, pinned - own_cpu_s) / wall
        foreign_total = max(0.0, sum(delta.values()) - own_cpu_s) / wall
        return {"foreign_pinned_cores": round(foreign_pinned, 3),
                "foreign_total_cores": round(foreign_total, 3),
                "noisy": foreign_pinned > NOISY_CORES}


def run_loadgen(args, target, server, ref, in_flight, associations, threads):
    cmd = [str(args.loadgen), "--port", str(PORTS[target]), "--ref", REFS[ref],
           "--in-flight", str(in_flight), "--associations", str(associations),
           "--threads", str(threads), "--warmup", str(args.warmup),
           "--duration", str(args.duration)]
    server_cpu0 = process_cpu_s(server.pid)
    usage0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    noise = Interference()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         preexec_fn=pin(CLIENT_CPUS))
    time.sleep(args.warmup + args.duration / 2)
    server_threads = process_threads(server.pid)
    try:
        out, err = p.communicate(timeout=args.warmup + args.duration + 60 + associations / 10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return {"failed": "timeout"}
    usage1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    server_cpu = process_cpu_s(server.pid) - server_cpu0
    client_cpu = (usage1.ru_utime + usage1.ru_stime) - (usage0.ru_utime + usage0.ru_stime)
    noise = noise.finish(server_cpu + client_cpu)
    if p.returncode != 0:
        return {"failed": f"exit {p.returncode}: {err.strip()}", **noise}
    r = json.loads(out)
    r.update(noise)
    reads = max(r["reads"], 1)
    # Includes warm-up, connect and release, a small overstatement for both peers alike.
    measured = reads * (args.warmup + args.duration) / args.duration
    r["server_threads"] = server_threads
    r["server_cpu_us_per_read"] = round(server_cpu * 1e6 / measured, 2)
    r["client_cpu_us_per_read"] = round(client_cpu * 1e6 / measured, 2)
    r["server_cores"] = round(server_cpu / (args.warmup + args.duration), 3)
    r["client_cores"] = round(client_cpu / (args.warmup + args.duration), 3)
    if err.strip():
        r["stderr"] = err.strip()
    return r


def run_client(args, argv, runs):
    env = dict(os.environ, PATH=f"{args.peer_bin}:{os.environ['PATH']}")
    walls, failures = [], 0
    usage0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    noise = Interference()
    for _ in range(runs):
        t0 = time.perf_counter()
        p = subprocess.run(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           preexec_fn=pin(CLIENT_CPUS), timeout=30, check=False)
        walls.append((time.perf_counter() - t0) * 1000)
        failures += p.returncode != 0
    usage1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    own = (usage1.ru_utime + usage1.ru_stime) - (usage0.ru_utime + usage0.ru_stime)
    return {"wall_ms_median": round(statistics.median(walls), 3),
            "wall_ms_max": round(max(walls), 3), "runs": runs, "failures": failures,
            **noise.finish(own)}


def cells(args):
    """(kind, name, parameters, targets) of every cell of a round, in a fixed order."""
    both = ("libiec61850", "openiec61850")
    out = []
    if "reads" in args.only:
        for ref in REFS:
            for n in (1, 5, 16):
                out.append(("read", f"read/{ref}/in_flight:{n}",
                            {"ref": ref, "in_flight": n, "associations": 1, "threads": 1}, both))
    if "associations" in args.only:
        # The example server serves 2 concurrent associations; 4 records that it refuses the rest.
        for a in (1, 2, 4, 16, 64, 256):
            targets = both if a <= 4 else ("openiec61850",)
            out.append(("read", f"associations:{a}",
                        {"ref": "scalar", "in_flight": 1, "associations": a, "threads": 2},
                        targets))
    if "clients" in args.only:
        for name in client_commands(0):
            out.append(("client", f"client/{name}", {"client": name}, both))
    return out


def machine(args):
    def text(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
        except OSError:
            return ""
    cpu = next((l.split(":", 1)[1].strip() for l in text(["lscpu"]).splitlines()
                if l.startswith("Model name")), "?")
    mem = int(Path("/proc/meminfo").read_text(encoding="ascii").split()[1]) // (1024 * 1024)
    sha = args.peer_bin.parent / "source.sha256"
    return {
        "cpu": cpu, "cpus": os.cpu_count(), "memory_gib": mem, "kernel": platform.release(),
        "compiler": text(["c++", "--version"]).splitlines()[0],
        "cmake": text(["cmake", "--version"]).splitlines()[0],
        "openiec61850_commit": text(["git", "-C", str(Path(__file__).parent), "rev-parse", "HEAD"]),
        "tree_dirty": bool(text(["git", "-C", str(Path(__file__).parent), "status", "--short"])),
        "libiec61850_version": args.peer_version,
        "libiec61850_source_sha256": sha.read_text(encoding="ascii").strip() if sha.exists() else "",
        "build_type": "Release on both sides", "release_flags": args.flags,
        "transport": "TCP loopback, 127.0.0.1, no TLS",
        "server_cpus": sorted(SERVER_CPUS), "client_cpus": sorted(CLIENT_CPUS),
    }


def spread(values):
    values = sorted(values)
    q = statistics.quantiles(values, n=4, method="inclusive") if len(values) > 1 else values * 3
    return {"median": statistics.median(values), "q1": q[0], "q3": q[2],
            "min": values[0], "max": values[-1], "n": len(values)}


def summarise(samples):
    rows = []
    keys = sorted({(s["cell"], s["target"]) for s in samples})
    for cell, target in keys:
        group = [s for s in samples if (s["cell"], s["target"]) == (cell, target)]
        good = [s for s in group if "failed" not in s]
        metrics = (("wall_ms_median",) if cell.startswith("client/") else
                   ("reads_per_s", "p50_us", "p99_us", "server_cpu_us_per_read",
                    "client_cpu_us_per_read", "server_cores", "client_cores", "connect_p50_ms",
                    "associations_up"))
        row = {"cell": cell, "target": target, "samples": len(group),
               "failed_samples": len(group) - len(good),
               "noisy_samples": sum(1 for s in group if s.get("noisy")),
               "errors": sum(s.get("errors", 0) + s.get("failures", 0) for s in good),
               "connect_failures": sum(s.get("connect_failures", 0) for s in good)}
        for m in metrics:
            if good and m in good[0]:
                row[m] = spread([s[m] for s in good])
        rows.append(row)
    return rows


def paired_ratio(samples, cell, metric):
    """Per-round ours/theirs: the two samples of a round ran next to each other."""
    by = {(s["round"], s["target"]): s for s in samples if s["cell"] == cell and "failed" not in s}
    ratios = [by[(r, "openiec61850")][metric] / by[(r, "libiec61850")][metric]
              for r, t in by if t == "libiec61850" and (r, "openiec61850") in by
              and by[(r, "libiec61850")][metric]]
    return spread(ratios) if ratios else None


def report(samples, rows, context, out):
    (out / "raw.json").write_text(json.dumps({"context": context, "samples": samples}, indent=0),
                                  encoding="utf-8")
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cell", "target", "metric", "median", "q1", "q3", "min", "max", "n",
                    "noisy_samples", "failed_samples", "errors", "connect_failures"])
        for r in rows:
            for m, v in r.items():
                if isinstance(v, dict):
                    w.writerow([r["cell"], r["target"], m, *(round(v[k], 3) for k in
                                ("median", "q1", "q3", "min", "max")), v["n"], r["noisy_samples"],
                                r["failed_samples"], r["errors"], r["connect_failures"]])
    def fmt(v, digits=0):
        return (f"{v['median']:,.{digits}f} (IQR {v['q1']:,.{digits}f}-{v['q3']:,.{digits}f}, "
                f"range {v['min']:,.{digits}f}-{v['max']:,.{digits}f})")
    lines = ["| Cell | Target | Value | Other | Noisy/failed/errors |", "|---|---|---|---|---|"]
    for r in rows:
        flags = f"{r['noisy_samples']}/{r['failed_samples']}/{r['errors']}"
        if "wall_ms_median" in r:
            lines.append(f"| {r['cell']} | {r['target']} | {fmt(r['wall_ms_median'], 2)} ms | | "
                         f"{flags} |")
        elif "reads_per_s" in r:
            other = (f"p50 {fmt(r['p50_us'], 1)} us; p99 {r['p99_us']['median']:.0f} us; server "
                     f"{r['server_cpu_us_per_read']['median']:.1f} us CPU/read "
                     f"({r['server_cores']['median']:.2f} core); client "
                     f"{r['client_cores']['median']:.2f} core; connect "
                     f"{r['connect_p50_ms']['median']:.2f} ms; up "
                     f"{r['associations_up']['median']:.0f}")
            lines.append(f"| {r['cell']} | {r['target']} | {fmt(r['reads_per_s'])} reads/s | "
                         f"{other} | {flags} |")
    lines += ["", "Paired per-round ratio openiec61850 / libiec61850 (median, range):", ""]
    for cell in sorted({s["cell"] for s in samples}):
        metric = "wall_ms_median" if cell.startswith("client/") else "reads_per_s"
        ratio = paired_ratio(samples, cell, metric)
        if ratio:
            lines.append(f"- {cell} {metric}: {ratio['median']:.3f} "
                         f"({ratio['min']:.3f}-{ratio['max']:.3f})")
    noisy = sum(1 for s in samples if s.get("noisy"))
    total_foreign = [s["foreign_total_cores"] for s in samples if "foreign_total_cores" in s]
    lines += ["", f"Samples: {len(samples)}, noisy: {noisy} (foreign use of the pinned CPUs above "
              f"{NOISY_CORES} core). Foreign use of the whole machine, in cores: median "
              f"{statistics.median(total_foreign):.2f}, max {max(total_foreign):.2f}.", ""]
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


def main():
    p = argparse.ArgumentParser()
    for name in ("peer-version", "flags"):
        p.add_argument(f"--{name}", required=True)
    for name in ("peer-bin", "ours-bin", "icd", "out"):
        p.add_argument(f"--{name}", required=True, type=Path)
    p.add_argument("--rounds", type=int, default=7)
    p.add_argument("--duration", type=float, default=5)
    p.add_argument("--warmup", type=float, default=1)
    p.add_argument("--client-runs", type=int, default=100, help="per cell and round")
    p.add_argument("--only", default="reads,associations,clients")
    args = p.parse_args()
    args.only = args.only.split(",")
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    args.loadgen = args.ours_bin / "openiec61850_ref_loadgen"
    args.server = args.ours_bin / "openiec61850" / "tools" / "openiec61850-server"

    context = {"machine": machine(args),
               "method": {"rounds": args.rounds, "duration_s": args.duration,
                          "warmup_s": args.warmup, "client_runs": args.client_runs,
                          "noisy_threshold_cores": NOISY_CORES},
               "load_start": os.getloadavg(), "started": time.strftime("%FT%T%z"),
               "command": shlex.join(sys.argv[1:])}
    samples = []
    for round_no in range(args.rounds):
        servers = start_servers(args)
        try:
            for kind, cell, params, targets in cells(args):
                ordered = targets[::-1] if round_no % 2 else targets
                for target in ordered:
                    if kind == "read":
                        r = run_loadgen(args, target, servers[target], **params)
                    else:
                        r = run_client(args, client_commands(PORTS[target])[params["client"]],
                                       args.client_runs)
                    samples.append({"round": round_no, "cell": cell, "target": target, **r})
                    print(json.dumps(samples[-1]), flush=True)
        finally:
            stop_servers(servers)
    context["load_end"] = os.getloadavg()
    context["finished"] = time.strftime("%FT%T%z")
    report(samples, summarise(samples), context, args.out)


if __name__ == "__main__":
    main()
