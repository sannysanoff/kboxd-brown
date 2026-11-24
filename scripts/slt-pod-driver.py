#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the sqllogictest corpus against kbox, one container per test file.

Runs inside the pod and speaks the Docker Engine API of the shim on
127.0.0.1:2376. One container per file keeps a wedged guest to one file, and a
file that returns exit code 0 is a perfect result: the runner reports the
number of mismatches as its exit status.

Logs and the summary live on the shared volume, so a dropped exec does not lose
work: the next run skips every file that already passed.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CREATE_TIMEOUT = 120
START_TIMEOUT = 120
INSPECT_TIMEOUT = 20
DELETE_TIMEOUT = 30
POLL_SECONDS = 2.0
HINT_MARKERS = (
    "wrong result",
    "expected:",
    "got:",
    "errors out of",
    "unknown record type",
    "cannot open",
)


class ApiError(RuntimeError):
    pass


class Api:
    """Minimal Docker Engine client. One connection per call."""

    def __init__(self, base):
        self.base = base.rstrip("/")

    def call(self, method, path, body=None, timeout=30):
        url = self.base + path
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace").strip()
            try:
                detail = json.loads(detail).get("message", detail)
            except ValueError:
                pass
            raise ApiError(f"{method} {path}: {err.code} {detail}") from None
        except urllib.error.URLError as err:
            raise ApiError(f"{method} {path}: {err.reason}") from None

    def call_json(self, method, path, body=None, timeout=30):
        raw = self.call(method, path, body, timeout)
        if not raw.strip():
            return {}
        return json.loads(raw)


def collect_scripts(corpus, files=None, filt=None, limit=0):
    if files:
        with open(files, "r", encoding="utf-8") as fh:
            out = [line.strip() for line in fh if line.strip()]
    else:
        out = []
        for root, _dirs, names in os.walk(corpus):
            for name in names:
                # macOS sidecars from a tar copy would otherwise count as tests.
                if name.endswith(".test") and not name.startswith("._"):
                    out.append(os.path.relpath(os.path.join(root, name), corpus))
        out.sort()
    if filt:
        out = [rel for rel in out if filt in rel]
    if limit > 0:
        out = out[:limit]
    return out


def read_summary(path):
    done = {}
    if not os.path.exists(path):
        return done
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            done[parts[1]] = parts[2]
    return done


def hints(log_path, limit=3):
    out = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                if any(marker in stripped for marker in HINT_MARKERS):
                    out.append(stripped[:200])
                    if len(out) >= limit:
                        break
    except OSError:
        pass
    return out


class Runner:
    def __init__(self, args):
        self.args = args
        self.api = Api(args.api)
        self.lock = threading.Lock()
        self.counts = {}
        self.stop = threading.Event()
        self.summary_path = os.path.join(args.results, "summary.tsv")
        self.progress_path = os.path.join(args.results, "progress.txt")

    # ---- container lifecycle ---------------------------------------------

    def container_name(self, rel):
        digest = hashlib.sha1(rel.encode("utf-8")).hexdigest()[:12]
        return f"slt-{digest}"

    def create(self, rel):
        name = self.container_name(rel)
        logname = rel.replace("/", "__") + ".log"
        pod_log = os.path.join(self.args.results, logname)
        # The pod directory is bind-mounted at args.mount, so the guest sees
        # different paths than this process does.
        script = f"{self.args.mount}/test/{rel}"
        rel_res = os.path.relpath(self.args.results, self.args.root)
        log = f"{self.args.mount}/{rel_res}/{logname}"
        # Each file gets its own database directory. Two files that share one
        # directory would unlink each other's test.db.
        db = f"{self.args.db_dir}/{name}"
        pod_db = None
        if db.startswith(self.args.mount + "/"):
            pod_db = os.path.join(self.args.root, db[len(self.args.mount) + 1 :])
        cmd = (
            f"mkdir -p {db} && cd {db} && "
            f"exec {self.args.mount}/sqllogictest -verify {script} > {log} 2>&1"
        )
        body = {
            "Image": self.args.image,
            "Cmd": ["/bin/sh", "-c", cmd],
            "WorkingDir": "/",
            "Env": ["HOME=/tmp"],
            "HostConfig": {"Binds": [f"{self.args.root}:{self.args.mount}"]},
        }
        resp = self.api.call_json(
            "POST",
            "/containers/create?name=" + urllib.parse.quote(name),
            body,
            CREATE_TIMEOUT,
        )
        return resp["Id"], pod_log, pod_db

    def remove(self, cid, force):
        try:
            self.api.call(
                "DELETE",
                f"/containers/{cid}?force={1 if force else 0}",
                timeout=DELETE_TIMEOUT,
            )
        except ApiError:
            pass

    def run_one(self, rel):
        started = time.time()
        errors = 0
        cid = None
        pod_db = None
        log = os.path.join(self.args.results, rel.replace("/", "__") + ".log")
        result = "ERROR"
        try:
            cid, log, pod_db = self.create(rel)
            self.api.call("POST", f"/containers/{cid}/start", timeout=START_TIMEOUT)
            deadline = started + self.args.timeout
            misses = 0
            while True:
                try:
                    info = self.api.call_json(
                        "GET", f"/containers/{cid}/json", timeout=INSPECT_TIMEOUT
                    )
                    misses = 0
                except ApiError:
                    misses += 1
                    if misses >= 3:
                        result = "UNREACHABLE"
                        self.stop.set()
                        break
                    time.sleep(POLL_SECONDS)
                    continue
                state = info.get("State") or {}
                if not state.get("Running"):
                    errors = int(state.get("ExitCode") or 0)
                    result = "PASS" if errors == 0 else "FAIL"
                    break
                if time.time() > deadline:
                    result = "TIMEOUT"
                    break
                time.sleep(POLL_SECONDS)
        except ApiError as err:
            errors = 1
            if result != "UNREACHABLE":
                result = "ERROR"
            try:
                with open(os.path.join(self.args.results, "driver-errors.log"),
                          "a", encoding="utf-8") as fh:
                    fh.write(f"{rel}\t{err}\n")
            except OSError:
                pass
        finally:
            if cid is not None:
                if result in ("TIMEOUT", "ERROR", "UNREACHABLE"):
                    self.remove(cid, True)
                else:
                    self.remove(cid, False)
            if pod_db is not None:
                shutil.rmtree(pod_db, ignore_errors=True)

        elapsed = int(time.time() - started)
        detail = ""
        if result != "PASS":
            found = hints(log)
            if found:
                detail = " | " + " | ".join(found)

        with self.lock:
            now = time.strftime("%Y-%m-%dT%H:%M:%S")
            with open(self.summary_path, "a", encoding="utf-8") as fh:
                fh.write(f"{now}\t{rel}\t{result}\t{elapsed}\t{errors}\n")
            self.counts[result] = self.counts.get(result, 0) + 1
            self.write_progress()
            print(f"{rel}\t{result}\t{elapsed}s{detail}", flush=True)
        return result

    def write_progress(self):
        total = sum(self.counts.values())
        parts = " ".join(f"{k}={v}" for k, v in sorted(self.counts.items()))
        with open(self.progress_path, "w", encoding="utf-8") as fh:
            fh.write(f"done={total} {parts}\n")

    # ---- sweep ------------------------------------------------------------

    def sweep(self, scripts):
        if not scripts:
            print("nothing to run", file=sys.stderr)
            return 0

        if self.args.pull:
            repo, _, tag = self.args.image.partition(":")
            query = urllib.parse.urlencode(
                {"fromImage": repo, "tag": tag or "latest"}
            )
            print(f"pull {self.args.image}", flush=True)
            try:
                self.api.call("POST", "/images/create?" + query, timeout=600)
            except ApiError as err:
                print(f"pull failed: {err}", file=sys.stderr)

        os.makedirs(self.args.results, exist_ok=True)
        if self.args.workers <= 1:
            for rel in scripts:
                if self.stop.is_set():
                    break
                self.run_one(rel)
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.args.workers
            ) as pool:
                futures = []
                for rel in scripts:
                    if self.stop.is_set():
                        break
                    futures.append(pool.submit(self.run_one, rel))
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()

        bad = self.counts.get("FAIL", 0) + self.counts.get("TIMEOUT", 0)
        bad += self.counts.get("ERROR", 0) + self.counts.get("UNREACHABLE", 0)
        print("== summary " + " ".join(f"{k}={v}" for k, v in sorted(self.counts.items())))
        return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:2376")
    ap.add_argument("--image", default="alpine:3.21")
    ap.add_argument("--root", default="/data/slt",
                    help="corpus root on the pod filesystem (corpus at ROOT/test)")
    ap.add_argument("--mount", default="/data",
                    help="guest path that ROOT is bind-mounted at")
    ap.add_argument("--results", default="/data/slt/results")
    ap.add_argument("--db-dir", default="/tmp",
                    help="guest directory for per-file test.db directories")
    ap.add_argument("--files", default=None,
                    help="file with one corpus-relative path per line")
    ap.add_argument("--filter", default=None, help="substring filter on the path")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=1800,
                    help="per-file wall clock limit in seconds")
    ap.add_argument("--retry-failed", action="store_true",
                    help="rerun files whose last result was not PASS")
    ap.add_argument("--no-pull", dest="pull", action="store_false")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    scripts = collect_scripts(args.root + "/test", args.files, args.filter, args.limit)
    os.makedirs(args.results, exist_ok=True)

    done = read_summary(os.path.join(args.results, "summary.tsv"))
    if not args.retry_failed:
        scripts = [rel for rel in scripts if done.get(rel) != "PASS"]

    print(f"{len(scripts)} files selected, {len(done)} recorded earlier")
    if args.dry_run:
        for rel in scripts:
            print(rel)
        return 0

    return Runner(args).sweep(scripts)


if __name__ == "__main__":
    sys.exit(main())
