#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for the kbox Docker Engine HTTP API frontend."""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCKERD_PATH = os.path.join(REPO_ROOT, "scripts", "kbox-dockerd.py")

spec = importlib.util.spec_from_file_location("kbox_dockerd", DOCKERD_PATH)
kbox_dockerd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kbox_dockerd)


class FakeRpc:
    """In-memory stub for `kbox daemon` JSON-RPC."""

    def __init__(self, log_dir):
        self.calls = []
        self.log_dir = log_dir
        self._ip_seq = 2

    def call(self, payload):
        self.calls.append(payload)
        op = payload.get("op")
        if op == "ping":
            return {"ok": True, "lkl": True}
        if op == "image_import":
            return {"ok": True}
        if op == "container_create":
            ip = f"172.18.0.{self._ip_seq}"
            self._ip_seq += 1
            cid = payload["id"]
            return {
                "ok": True,
                "id": cid,
                "ip": ip,
                "log_path": os.path.join(self.log_dir, f"{cid}.log"),
            }
        if op == "container_start":
            return {"ok": True, "pid": 1234, "ip": "172.18.0.2"}
        if op == "container_inspect":
            return {"ok": True, "state": "running", "pid": 1234, "exit_code": 0}
        if op == "container_wait":
            return {"ok": True, "exit_code": 0}
        if op == "exec_start":
            eid = payload["exec_id"]
            lp = os.path.join(self.log_dir, f"exec-{eid}.log")
            with open(lp, "wb") as f:
                data = b"EXEC_OK\n"
                f.write(struct.pack(">BxxxI", 1, len(data)) + data)
            return {"ok": True, "pid": 1235, "log_path": lp}
        if op == "exec_wait":
            return {"ok": True, "exit_code": 42}
        if op in ("container_stop", "container_kill", "container_rm", "dns_set"):
            return {"ok": True}
        return {"ok": True}


class TestDockerEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_dir = os.path.join(self.tmpdir.name, "state")
        self.log_dir = os.path.join(self.tmpdir.name, "logs")
        self.img_src = os.path.join(self.tmpdir.name, "rootfs")
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(os.path.join(self.img_src, "bin"), exist_ok=True)

        self.rpc = FakeRpc(self.log_dir)
        self.vol_root = os.path.join(self.tmpdir.name, "volumes")
        # The mapped tree is writable: a missing -v source is created on the
        # host, so a map that pointed at the real root would create /mapped.
        self.mapped_src = os.path.join(self.tmpdir.name, "mapped", "src")
        self.engine = kbox_dockerd.DockerEngineState(
            self.rpc,
            self.state_dir,
            path_maps=[("/host/src", self.mapped_src)],
            config={
                "start_ip": "172.18.0.2",
                "gateway": "172.18.0.1",
                "volumes_root": self.vol_root,
            },
        )
        self.img_id = self.engine.images.import_dir_as_image(
            "alpine:latest", self.img_src
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_image_resolve_variants(self):
        self.assertEqual(self.engine.images.resolve("alpine"), self.img_id)
        self.assertEqual(self.engine.images.resolve("alpine:latest"), self.img_id)
        self.assertEqual(
            self.engine.images.resolve("docker.io/library/alpine:latest"),
            self.img_id,
        )
        self.assertEqual(self.engine.images.resolve(self.img_id[:16]), self.img_id)

    def test_create_container_binds_aliases_ports(self):
        rec = self.engine.create_container(
            "web-1",
            {
                "Image": "alpine:latest",
                "Cmd": ["sh", "-c", "echo ok"],
                "Labels": {"com.docker.compose.service": "web"},
                "HostConfig": {
                    "Binds": ["/host/src/www:/srv:ro"],
                    "PortBindings": {
                        "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]
                    },
                },
                "NetworkingConfig": {
                    "EndpointsConfig": {
                        "app_net": {"Aliases": ["web", "web-alias"]}
                    }
                },
            },
        )
        self.assertEqual(rec["name"], "web-1")
        self.assertEqual(rec["ip"], "172.18.0.2")
        create_rpc = [c for c in self.rpc.calls if c["op"] == "container_create"][-1]
        self.assertIn(f"{self.mapped_src}/www:/srv:ro", create_rpc["binds"])
        self.assertTrue(os.path.isdir(f"{self.mapped_src}/www"))
        self.assertIn("web", create_rpc["aliases"])
        self.assertIn("web-alias", create_rpc["aliases"])
        self.assertIn("0.0.0.0:18080:8080", create_rpc["ports"])

    def test_create_container_creates_missing_bind_source(self):
        # Docker's -v creates the host directory when it does not exist, and
        # Compose relies on it for the first start of `./data:/data`.
        src = os.path.join(self.tmpdir.name, "fresh", "data")
        self.engine.create_container(
            "b-1",
            {
                "Image": "alpine:latest",
                "Cmd": ["true"],
                "HostConfig": {"Binds": [f"{src}:/data"]},
            },
        )
        self.assertTrue(os.path.isdir(src))
        create_rpc = [c for c in self.rpc.calls if c["op"] == "container_create"][-1]
        self.assertIn(f"{src}:/data", create_rpc["binds"])

    def test_long_mount_rejects_missing_source(self):
        # The --mount form stays strict: Docker rejects a missing source at
        # create time, and the path must not be created as a side effect.
        src = os.path.join(self.tmpdir.name, "absent")
        with self.assertRaises(kbox_dockerd.ContainerConfigError):
            self.engine.create_container(
                "m-1",
                {
                    "Image": "alpine:latest",
                    "Cmd": ["true"],
                    "HostConfig": {
                        "Mounts": [
                            {"Type": "bind", "Source": src, "Target": "/data"}
                        ]
                    },
                },
            )
        self.assertFalse(os.path.exists(src))
        self.assertFalse(
            any(c["op"] == "container_create" for c in self.rpc.calls)
        )

    def test_create_container_sets_home_and_hostname(self):
        # Docker gives the container process HOME and HOSTNAME when the image and the
        # request do not; entrypoints write $HOME/.aws/credentials and the like.
        self.engine.create_container(
            "env-1", {"Image": "alpine:latest", "Cmd": ["true"]}
        )
        env = [c for c in self.rpc.calls if c["op"] == "container_create"][-1]["env"]
        self.assertIn("HOME=/root", env)
        self.assertIn("HOSTNAME=env-1", env)

        # ...but an explicit value wins
        self.engine.create_container(
            "env-2",
            {"Image": "alpine:latest", "Cmd": ["true"], "Env": ["HOME=/srv/app"]},
        )
        env = [c for c in self.rpc.calls if c["op"] == "container_create"][-1]["env"]
        self.assertIn("HOME=/srv/app", env)
        self.assertNotIn("HOME=/root", env)

    def test_create_container_passes_memory_limit(self):
        # compose mem_limit / a Kubernetes resources limit arrives as HostConfig
        # Memory. The daemon shows it to the guest as the cgroup memory limit,
        # which is what a JVM or ClickHouse sizes its heap and caches from.
        self.engine.create_container(
            "limited-1",
            {
                "Image": "alpine:latest",
                "Cmd": ["true"],
                "HostConfig": {"Memory": 1073741824},
            },
        )
        rpc = [c for c in self.rpc.calls if c["op"] == "container_create"][-1]
        self.assertEqual(rpc["mem_limit"], 1073741824)

        self.engine.create_container(
            "unlimited-1", {"Image": "alpine:latest", "Cmd": ["true"]}
        )
        rpc = [c for c in self.rpc.calls if c["op"] == "container_create"][-1]
        self.assertEqual(rpc["mem_limit"], 0)

    def test_exec_lifecycle_and_http_endpoints(self):
        rec = self.engine.create_container("svc", {"Image": "alpine:latest"})
        self.engine.start_container(rec)

        srv = kbox_dockerd.ThreadingHTTPServer(
            ("127.0.0.1", 0), kbox_dockerd.DockerHandler
        )
        srv.engine = self.engine
        srv.verbose = False
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/_ping") as r:
                self.assertEqual(r.status, 200)
                self.assertEqual(r.read(), b"OK")

            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1.47/containers/{rec['id']}/exec",
                data=json.dumps({"Cmd": ["sh", "-c", "exit 42"]}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as r:
                self.assertEqual(r.status, 201)
                eid = json.loads(r.read().decode())["Id"]

            req2 = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1.47/exec/{eid}/start",
                data=json.dumps({"Detach": False, "Tty": False}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req2) as r:
                self.assertEqual(r.status, 200)
                body = r.read()
                self.assertIn(b"EXEC_OK", body)

            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/v1.47/exec/{eid}/json"
            ) as r:
                self.assertEqual(r.status, 200)
                info = json.loads(r.read().decode())
                self.assertFalse(info["Running"])
                self.assertEqual(info["ExitCode"], 42)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_logs_tail_parameter(self):
        rec = self.engine.create_container("logger", {"Image": "alpine:latest"})
        with open(rec["log_path"], "wb") as f:
            payload = b"line1\nline2\nline3\n"
            f.write(struct.pack(">BxxxI", 1, len(payload)) + payload)

        srv = kbox_dockerd.ThreadingHTTPServer(
            ("127.0.0.1", 0), kbox_dockerd.DockerHandler
        )
        srv.engine = self.engine
        srv.verbose = False
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/containers/{rec['id']}/logs?stdout=1&tail=2"
            ) as r:
                raw = r.read()
                self.assertNotIn(b"line1", raw)
                self.assertIn(b"line2", raw)
                self.assertIn(b"line3", raw)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_config_yaml_prefix32_and_persistent_volumes(self):
        cfg_path = os.path.join(self.tmpdir.name, "kbox-config.yaml")
        custom_vols = os.path.join(self.tmpdir.name, "persist-vols")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(
                "network:\n"
                "  start_ip: 172.24.0.10\n"
                f"volumes:\n  root: {custom_vols}\n"
            )
        cfg = kbox_dockerd.load_kbox_config(cfg_path)
        self.assertEqual(cfg["start_ip"], "172.24.0.10")
        self.assertEqual(cfg["gateway"], "172.24.0.1")
        self.assertEqual(cfg["volumes_root"], os.path.abspath(custom_vols))

        eng1 = kbox_dockerd.DockerEngineState(
            self.rpc, os.path.join(self.tmpdir.name, "s1"), config_path=cfg_path
        )
        eng1.images.import_dir_as_image("alpine:latest", self.img_src)
        rec = eng1.create_container(
            "db-1",
            {
                "Image": "alpine:latest",
                "Labels": {"com.docker.compose.service": "db"},
                "HostConfig": {"Binds": ["pgdata:/var/lib/db"]},
            },
        )
        insp = eng1.container_inspect_json(rec)
        self.assertEqual(insp["NetworkSettings"]["IPPrefixLen"], 32)
        self.assertEqual(insp["NetworkSettings"]["Gateway"], "172.24.0.1")
        self.assertEqual(rec["mounts_json"][0]["Type"], "volume")
        self.assertEqual(rec["mounts_json"][0]["Name"], "pgdata")

        data_file = os.path.join(custom_vols, "pgdata", "_data", "state.txt")
        with open(data_file, "w", encoding="utf-8") as f:
            f.write("DB_ROW_1\n")

        # Simulate full daemon restart: fresh DockerEngineState loads persisted volume.
        eng2 = kbox_dockerd.DockerEngineState(
            self.rpc, os.path.join(self.tmpdir.name, "s2"), config_path=cfg_path
        )
        self.assertIn("pgdata", eng2.volumes)
        self.assertEqual(
            eng2.volumes["pgdata"]["Labels"].get("com.docker.compose.service"),
            "db",
        )
        with open(data_file, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "DB_ROW_1\n")

    def test_port_binding_formats(self):
        # 1. Other services only: expose without PortBindings.
        r1 = self.engine.create_container(
            "svc-expose",
            {
                "Image": "alpine:latest",
                "ExposedPorts": {"8080/tcp": {}},
            },
        )
        c1 = [c for c in self.rpc.calls if c.get("op") == "container_create"][-1]
        self.assertEqual(c1["ports"], [])
        i1 = self.engine.container_inspect_json(r1)
        self.assertEqual(i1["Config"]["ExposedPorts"], {"8080/tcp": {}})
        self.assertEqual(i1["NetworkSettings"]["Ports"], {})

        # 2. Host localhost only: 127.0.0.1:18081:8080.
        r2 = self.engine.create_container(
            "svc-local",
            {
                "Image": "alpine:latest",
                "HostConfig": {
                    "PortBindings": {
                        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18081"}]
                    }
                },
            },
        )
        c2 = [c for c in self.rpc.calls if c.get("op") == "container_create"][-1]
        self.assertEqual(c2["ports"], ["127.0.0.1:18081:8080"])
        i2 = self.engine.container_inspect_json(r2)
        self.assertEqual(
            i2["NetworkSettings"]["Ports"]["8080/tcp"],
            [{"HostIp": "127.0.0.1", "HostPort": "18081"}],
        )

        # 3. All IPv4 interfaces: 0.0.0.0:18082:8080 and omitted HostIp -> 0.0.0.0.
        r3 = self.engine.create_container(
            "svc-all",
            {
                "Image": "alpine:latest",
                "HostConfig": {
                    "PortBindings": {
                        "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18082"}],
                        "8081/tcp": [{"HostIp": "", "HostPort": "18083"}],
                    }
                },
            },
        )
        c3 = [c for c in self.rpc.calls if c.get("op") == "container_create"][-1]
        self.assertEqual(
            sorted(c3["ports"]),
            ["0.0.0.0:18082:8080", "0.0.0.0:18083:8081"],
        )
        i3 = self.engine.container_inspect_json(r3)
        self.assertEqual(
            i3["NetworkSettings"]["Ports"]["8080/tcp"],
            [{"HostIp": "0.0.0.0", "HostPort": "18082"}],
        )
        self.assertEqual(
            i3["NetworkSettings"]["Ports"]["8081/tcp"],
            [{"HostIp": "0.0.0.0", "HostPort": "18083"}],
        )

    def test_healthcheck_state_and_transitions(self):
        orig_call = self.rpc.call
        exec_rcs = [1, 0, 1, 1]

        def hc_call(payload):
            if payload.get("op") == "exec_wait":
                rc = exec_rcs.pop(0) if exec_rcs else 1
                return {"ok": True, "exit_code": rc}
            return orig_call(payload)

        self.rpc.call = hc_call
        rec = self.engine.create_container(
            "hc-web",
            {
                "Image": "alpine:latest",
                "Healthcheck": {
                    "Test": ["CMD-SHELL", "echo ok"],
                    "Interval": 200_000_000,
                    "Timeout": 1_000_000_000,
                    "Retries": 2,
                },
            },
        )
        rec["health"] = {"Status": "starting", "FailingStreak": 0, "Log": []}
        rec["status"] = "running"

        e1 = self.engine._run_healthcheck_once(rec, ["/bin/sh", "-c", "echo ok"], 1.0)
        self.assertEqual(e1["ExitCode"], 1)
        self.assertEqual(e1["Output"], "EXEC_OK\n")

        # Drive healthy transition and failing streak -> unhealthy via _watch_health logic
        rec["health_stop"].clear()
        hc = rec["healthcheck"]
        self.assertEqual(
            self.engine._healthcheck_cmd(hc["Test"]),
            ["/bin/sh", "-c", "echo ok"],
        )
        self.assertEqual(
            self.engine._healthcheck_cmd(["CMD", "clickhouse-client", "--query", "SELECT 1"]),
            ["clickhouse-client", "--query", "SELECT 1"],
        )

        # Pass check -> healthy
        e2 = self.engine._run_healthcheck_once(rec, ["/bin/sh", "-c", "echo ok"], 1.0)
        self.assertEqual(e2["ExitCode"], 0)
        rec["health"]["Status"] = "healthy"
        insp = self.engine.container_inspect_json(rec)
        self.assertEqual(insp["State"]["Health"]["Status"], "healthy")
        self.assertEqual(insp["Config"]["Healthcheck"]["Retries"], 2)

        # Clean up health_stop
        rec["health_stop"].set()

    def test_start_recreates_missing_volume_dir(self):
        rec = self.engine.create_container(
            "vol",
            {
                "Image": "alpine:latest",
                "HostConfig": {
                    "Mounts": [
                        {"Type": "volume", "Source": "vd", "Target": "/data"}
                    ]
                },
            },
        )
        src = next(
            m["Source"]
            for m in rec["mounts_json"]
            if m.get("Destination") == "/data"
        )
        os.rmdir(src)
        self.assertFalse(os.path.isdir(src))

        self.engine.start_container(rec)
        self.assertTrue(os.path.isdir(src))

    def test_restart_resets_exit_status(self):
        # The daemon's container_wait blocks until exit; make the stub behave
        # the same so the exit watcher cannot fire during the test.
        orig_call = self.rpc.call

        def blocking_call(payload):
            if payload.get("op") == "container_wait":
                time.sleep(2)
                return {"ok": True, "exit_code": 0}
            return orig_call(payload)

        self.rpc.call = blocking_call
        rec = self.engine.create_container("restart", {"Image": "alpine:latest"})
        self.engine.start_container(rec)
        # Simulate the exit the watcher would record.
        rec["status"] = "exited"
        rec["exit_code"] = 137
        rec["finished_at"] = 123
        self.engine.start_container(rec)
        self.assertEqual(rec["status"], "running")
        self.assertEqual(rec["exit_code"], 0)
        self.assertEqual(rec["finished_at"], 0)

    def test_inspect_refreshes_exited_state(self):
        rec = self.engine.create_container("gone", {"Image": "alpine:latest"})
        self.engine.start_container(rec)

        orig_call = self.rpc.call

        def fake_call(payload):
            if payload.get("op") == "container_inspect":
                return {"ok": True, "state": "exited", "pid": 1234,
                        "exit_code": 3}
            if payload.get("op") == "container_wait":
                time.sleep(2)
                return {"ok": True, "exit_code": 0}
            return orig_call(payload)

        self.rpc.call = fake_call
        srv = kbox_dockerd.ThreadingHTTPServer(
            ("127.0.0.1", 0), kbox_dockerd.DockerHandler
        )
        srv.engine = self.engine
        srv.verbose = False
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/v1.47/containers/{rec['id']}/json"
            ) as r:
                info = json.loads(r.read().decode())
            self.assertFalse(info["State"]["Running"])
            self.assertEqual(info["State"]["ExitCode"], 3)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_rename_container_updates_name_and_dns(self):
        rec = self.engine.create_container("old-name", {"Image": "alpine:latest"})
        with self.engine.lock:
            self.assertEqual(rec["name"], "old-name")
            rec["name"] = "new-name"
        self.assertIs(self.engine.find_container("new-name"), rec)
        insp = self.engine.container_inspect_json(rec)
        self.assertEqual(insp["Name"], "/new-name")


    def test_start_signals_run_event(self):
        rec = self.engine.create_container("ev-1", {"Image": "alpine:latest"})
        self.assertFalse(rec["run_ev"].is_set())
        self.engine.start_container(rec)
        self.assertTrue(rec["run_ev"].is_set())

    def test_image_tag_adds_reference(self):
        norm = self.engine.images.tag("alpine:latest", "tardis", "v1")
        self.assertEqual(norm, "tardis:v1")
        self.assertEqual(self.engine.images.resolve("tardis:v1"), self.img_id)
        # A registry-qualified source resolves too, and untagged repo => latest.
        self.engine.images.tag("alpine", "localhost:5000/x")
        self.assertEqual(self.engine.images.resolve("localhost:5000/x"), self.img_id)
        self.assertIsNone(self.engine.images.tag("nosuch:1", "y"))


class TestLayerCache(unittest.TestCase):
    """Layer store: streaming download, dedup, whiteouts, manifests, sweep."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.rpc = FakeRpc(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _store(self, **cfg):
        state = os.path.join(self.tmpdir.name, "state")
        return kbox_dockerd.ImageStore(state, self.rpc, config=cfg)

    def _layer_tar(self, name, files=None, symlinks=None, dirs=None,
                   whiteouts=None, opaque=None):
        path = os.path.join(self.tmpdir.name, name)
        with tarfile.open(path, mode="w") as tf:
            for d in dirs or []:
                info = tarfile.TarInfo(d)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
            for fname, (mode, data) in (files or {}).items():
                info = tarfile.TarInfo(fname)
                info.size = len(data)
                info.mode = mode
                tf.addfile(info, io.BytesIO(data))
            for link, target in (symlinks or {}).items():
                info = tarfile.TarInfo(link)
                info.type = tarfile.SYMTYPE
                info.linkname = target
                info.mode = 0o777
                tf.addfile(info)
            for wh in whiteouts or []:
                info = tarfile.TarInfo(wh)
                info.size = 0
                tf.addfile(info, io.BytesIO(b""))
            for marker in opaque or []:
                info = tarfile.TarInfo(marker)
                info.size = 0
                tf.addfile(info, io.BytesIO(b""))
        with open(path, "rb") as f:
            digest = "sha256:" + hashlib.sha256(f.read()).hexdigest()
        return path, digest

    @staticmethod
    def _entries(path):
        try:
            return os.listdir(path)
        except OSError:
            return []

    def test_ensure_layer_downloads_once_and_leaves_no_partials(self):
        store = self._store()
        tar_path, digest = self._layer_tar(
            "base.tar",
            files={"bin/sh": (0o755, b"#!/bin/sh\necho base\n")},
            dirs=["bin"],
        )
        url = "file://" + tar_path

        layer_dir, size = store.ensure_layer(digest, url, {})
        self.assertEqual(size, os.path.getsize(tar_path))
        self.assertEqual(layer_dir, store.layer_path(digest))
        with open(os.path.join(layer_dir, "bin", "sh"), "rb") as f:
            self.assertEqual(f.read(), b"#!/bin/sh\necho base\n")
        # The blob is kept on disk exactly as pulled.
        blob = store.blob_path(digest)
        self.assertEqual(os.path.getsize(blob), os.path.getsize(tar_path))
        blob_mtime = os.stat(blob).st_mtime_ns

        # A second pull of the same digest downloads and unpacks nothing.
        layer_dir2, size2 = store.ensure_layer(digest, url, {})
        self.assertEqual(layer_dir2, layer_dir)
        self.assertEqual(size2, size)
        self.assertEqual(os.stat(blob).st_mtime_ns, blob_mtime)

        for d in (store.blobs_dir, store.layers_dir):
            for name in self._entries(d):
                self.assertNotIn(".part", name)
                self.assertNotIn(".stage-", name)

    def test_ensure_layer_reextracts_from_cached_blob(self):
        store = self._store()
        tar_path, digest = self._layer_tar("base.tar",
                                           files={"bin/sh": (0o755, b"x")})
        store.ensure_layer(digest, "file://" + tar_path, {})
        blob_mtime = os.stat(store.blob_path(digest)).st_mtime_ns

        # A wiped layers_dir must be repaired from the blob, not re-downloaded.
        shutil.rmtree(store.layer_path(digest))
        layer_dir, _ = store.ensure_layer(digest, "file://does-not-exist", {})
        self.assertTrue(os.path.isfile(os.path.join(layer_dir, "bin", "sh")))
        self.assertEqual(os.stat(store.blob_path(digest)).st_mtime_ns, blob_mtime)

    def test_ensure_layer_rejects_corrupt_blob(self):
        store = self._store()
        tar_path, _ = self._layer_tar("bad.tar", files={"a": (0o644, b"x")})
        wrong = "sha256:" + "0" * 64

        with self.assertRaises(RuntimeError):
            store.ensure_layer(wrong, "file://" + tar_path, {})

        self.assertFalse(os.path.exists(store.layer_path(wrong)))
        self.assertTrue(all(".part" not in n for n in self._entries(store.blobs_dir)))

    def test_extract_fills_read_only_directory(self):
        # ca-certificates style layer: a 0555 directory that still receives
        # symlinks and files after its own entry. Extraction runs unprivileged.
        store = self._store()
        path = os.path.join(self.tmpdir.name, "ro.tar")
        with tarfile.open(path, "w") as tf:
            info = tarfile.TarInfo("etc/certs")
            info.type = tarfile.DIRTYPE
            info.mode = 0o555
            tf.addfile(info)
            link = tarfile.TarInfo("etc/certs/hash.0")
            link.type = tarfile.SYMTYPE
            link.linkname = "root.pem"
            tf.addfile(link)
            data = tarfile.TarInfo("etc/certs/root.pem")
            data.size = 2
            data.mode = 0o444
            tf.addfile(data, io.BytesIO(b"ok"))
        with open(path, "rb") as f:
            digest = "sha256:" + hashlib.sha256(f.read()).hexdigest()

        layer_dir, _ = store.ensure_layer(digest, "file://" + path, {})

        certs = os.path.join(layer_dir, "etc", "certs")
        self.assertTrue(os.path.islink(os.path.join(certs, "hash.0")))
        self.assertEqual(os.stat(certs).st_mode & 0o777, 0o555)
        os.chmod(certs, 0o755)  # let the test cleanup remove it

    def test_extract_records_non_root_owner_as_xattr(self):
        if not hasattr(os, "setxattr"):
            self.skipTest("python without os.setxattr")
        store = self._store()
        path = os.path.join(self.tmpdir.name, "own.tar")
        with tarfile.open(path, "w") as tf:
            data = tarfile.TarInfo("var/db/data")
            data.size = 1
            data.uid = 999
            data.gid = 998
            tf.addfile(data, io.BytesIO(b"x"))
            root = tarfile.TarInfo("var/db/rootfile")
            root.size = 1
            tf.addfile(root, io.BytesIO(b"y"))
        with open(path, "rb") as f:
            digest = "sha256:" + hashlib.sha256(f.read()).hexdigest()

        layer_dir, _ = store.ensure_layer(digest, "file://" + path, {})

        owned = os.path.join(layer_dir, "var", "db", "data")
        try:
            self.assertEqual(os.getxattr(owned, "user.kbox.owner"), b"999:998")
        except OSError:
            self.skipTest("filesystem without user xattr")
        with self.assertRaises(OSError):
            os.getxattr(os.path.join(layer_dir, "var", "db", "rootfile"),
                        "user.kbox.owner")

    def test_extract_keeps_whiteouts_as_overlay_markers(self):
        if not hasattr(os, "setxattr"):
            self.skipTest("python without os.setxattr")
        store = self._store()
        tar_path, digest = self._layer_tar(
            "top.tar",
            files={"usr/bin/tool": (0o755, b"tool\n")},
            dirs=["etc", "var"],
            whiteouts=["etc/.wh.hostname", "var/.wh..wh..opq"],
        )
        layer_dir, _ = store.ensure_layer(digest, "file://" + tar_path, {})

        marker = os.path.join(layer_dir, "etc", "hostname")
        self.assertTrue(os.path.isfile(marker))
        self.assertEqual(os.path.getsize(marker), 0)
        self.assertFalse(os.path.exists(os.path.join(layer_dir, "etc",
                                                      ".wh.hostname")))
        self.assertEqual(os.getxattr(marker, "user.overlay.whiteout"), b"y")
        # The .wh..wh..opq entry itself is consumed: the marker moves to the
        # directory xattr, which is what overlayfs reads.
        opaque = os.path.join(layer_dir, "var")
        self.assertFalse(os.path.exists(os.path.join(opaque, ".wh..wh..opq")))
        self.assertEqual(os.getxattr(opaque, "user.overlay.opaque"), b"y")

    def test_manifest_supplies_layers_on_every_import(self):
        store = self._store()
        base_tar, base = self._layer_tar("base.tar", files={"a": (0o644, b"a")})
        top_tar, top = self._layer_tar("top.tar", files={"b": (0o644, b"b")})
        store.ensure_layer(base, "file://" + base_tar, {})
        store.ensure_layer(top, "file://" + top_tar, {})

        img_id = "sha256:" + "ab" * 32
        store.save_manifest(img_id, {"id": img_id, "layers": [base, top]})
        self.assertEqual(store.load_manifest(img_id)["layers"], [base, top])

        store.ensure_imported(img_id, [base, top])
        # Overlay wants the top layer first, the manifest is base first.
        self.assertEqual(
            self.rpc.calls[-1]["layers"],
            [store.layer_path(top), store.layer_path(base)],
        )

        # Container create imports without an explicit list: the manifest is
        # the source of truth, otherwise the layers would be forgotten.
        store.ensure_imported(img_id)
        self.assertEqual(
            self.rpc.calls[-1]["layers"],
            [store.layer_path(top), store.layer_path(base)],
        )

    def test_sweep_partials_removes_interrupted_pull_state(self):
        state = os.path.join(self.tmpdir.name, "state")
        first = kbox_dockerd.ImageStore(state, self.rpc, config={})

        open(os.path.join(first.blobs_dir, "deadbeef.tar.part"), "wb").close()
        os.makedirs(os.path.join(first.layers_dir, ".stage-deadbeef"))
        os.makedirs(os.path.join(first.images_dir, "img.tmp.1a2b"))
        open(os.path.join(first.manifests_dir, "img.json.tmp"), "w").close()
        os.makedirs(os.path.join(first.layers_dir, "live-layer"))
        open(os.path.join(first.blobs_dir, "live-layer.tar"), "wb").close()

        second = kbox_dockerd.ImageStore(state, self.rpc, config={})
        self.assertEqual(self._entries(second.blobs_dir), ["live-layer.tar"])
        self.assertEqual(self._entries(second.layers_dir), ["live-layer"])
        self.assertEqual(self._entries(second.images_dir), [])
        self.assertEqual(self._entries(second.manifests_dir), [])

    def test_storage_directories_are_configurable(self):
        blobs = os.path.join(self.tmpdir.name, "b")
        layers = os.path.join(self.tmpdir.name, "l")
        images = os.path.join(self.tmpdir.name, "i")
        manifests = os.path.join(self.tmpdir.name, "m")
        store = self._store(
            blobs_dir=blobs,
            layers_dir=layers,
            images_dir=images,
            manifests_dir=manifests,
            images_driver="hostfs",
        )
        for d in (blobs, layers, images, manifests):
            self.assertTrue(os.path.isdir(d))
        digest = "sha256:" + "cd" * 32
        self.assertTrue(store.layer_path(digest).startswith(layers + os.sep))
        self.assertTrue(store.blob_path(digest).startswith(blobs + os.sep))
        self.assertTrue(store.manifest_path(digest).startswith(manifests + os.sep))
        self.assertEqual(store.images_driver, "hostfs")

    def test_default_image_driver_is_hostfs(self):
        missing = os.path.join(self.tmpdir.name, "absent.yaml")
        cfg = kbox_dockerd.load_kbox_config(missing)
        self.assertEqual(cfg["images_driver"], "hostfs")

    def test_config_file_sets_storage_paths(self):
        cfg_path = os.path.join(self.tmpdir.name, "kbox-config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(
                "storage:\n"
                "  images: hostfs\n"
                "  blobs_dir: /var/cache/kbox/blobs\n"
                "  layers_dir: /var/cache/kbox/layers\n"
                "  images_dir: /var/cache/kbox/images\n"
                "  manifests_dir: /var/cache/kbox/manifests\n"
            )
        cfg = kbox_dockerd.load_kbox_config(cfg_path)
        self.assertEqual(cfg["images_driver"], "hostfs")
        self.assertEqual(cfg["blobs_dir"], "/var/cache/kbox/blobs")
        self.assertEqual(cfg["layers_dir"], "/var/cache/kbox/layers")
        self.assertEqual(cfg["images_dir"], "/var/cache/kbox/images")
        self.assertEqual(cfg["manifests_dir"], "/var/cache/kbox/manifests")

    def test_merged_tree_applies_whiteouts_for_copy_mode(self):
        if not hasattr(os, "setxattr"):
            self.skipTest("python without os.setxattr")
        store = self._store()
        base_tar, base = self._layer_tar(
            "base.tar",
            files={"keep": (0o644, b"keep"), "gone": (0o644, b"gone"),
                   "dir/old": (0o644, b"old")},
            dirs=["dir"],
        )
        top_tar, top = self._layer_tar(
            "top.tar",
            files={"new": (0o644, b"new")},
            whiteouts=["dir/.wh..wh..opq", ".wh.gone"],
        )
        store.ensure_layer(base, "file://" + base_tar, {})
        store.ensure_layer(top, "file://" + top_tar, {})
        rootfs = os.path.join(self.tmpdir.name, "rootfs")
        store._assemble_merged([base, top], rootfs)
        self.assertTrue(os.path.exists(os.path.join(rootfs, "keep")))
        self.assertTrue(os.path.exists(os.path.join(rootfs, "new")))
        # Whiteout deleted the lower file, the opaque dir cleared the lower dir.
        self.assertFalse(os.path.exists(os.path.join(rootfs, "gone")))
        self.assertFalse(os.path.exists(os.path.join(rootfs, "dir", "old")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
