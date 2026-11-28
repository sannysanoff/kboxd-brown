#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Docker Engine REST API frontend backed by a single `kbox daemon` LKL instance.

Serves Docker Engine HTTP/1.1 API (compatible with Docker CLI 29.x and
Docker Compose v5.x) over TCP (--host 0.0.0.0:2375) and/or Unix socket.
"""

import argparse
import base64
import faulthandler
import glob
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import platform
import queue
import re
import secrets
import shlex
import shutil
import signal
import socket
import socketserver
import stat
import struct
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


API_VERSION = "1.47"
MIN_API_VERSION = "1.24"
SERVER_VERSION = "29.0.0-kbox"
DEFAULT_CONFIG_PATH = "~/.config/kbox-config.yaml"
DEFAULT_START_IP = "172.18.0.2"
DEFAULT_GATEWAY_IP = "172.18.0.1"
DEFAULT_VOLUMES_ROOT = "~/.local/share/kbox/volumes"


class _StripAuthOnCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Drop the registry bearer token when a redirect leaves the registry host.

    A registry answers a blob GET with a 307 to a CDN/S3 URL. urllib forwards
    the original request headers, so the Authorization header travels to the
    object store, which rejects the request with 400 Bad Request instead of
    serving the blob.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_host = urllib.parse.urlsplit(req.full_url).netloc
            if urllib.parse.urlsplit(newurl).netloc != old_host:
                new.headers.pop("Authorization", None)
                new.unredirected_hdrs.pop("Authorization", None)
        return new


_SAME_ORIGIN_OPENER = urllib.request.build_opener(_StripAuthOnCrossHostRedirect)


def load_registry_auth(path=None):
    """Read registry credentials from a docker config.json.

    Only the flat `auths` map is read. ECR hands out a short-lived basic
    credential (`AWS:<token>`) that the registry accepts directly on /v2/, so a
    username/password pair per registry host is all that is needed — no
    credential helpers, no SigV4. The file is optional: an install without one
    keeps the previous anonymous-plus-token behaviour.
    """
    candidates = []
    if path:
        candidates.append(path)
    else:
        env = os.environ.get("KBOX_DOCKER_CONFIG", "")
        if env:
            candidates.append(env)
        candidates.append(os.path.expanduser("~/.docker/config.json"))
    for cand in candidates:
        try:
            with open(cand, encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, ValueError):
            continue
        auths = cfg.get("auths") or {}
        out = {}
        for host, entry in auths.items():
            if not isinstance(entry, dict):
                continue
            user = entry.get("username") or entry.get("Username")
            pw = entry.get("password") or entry.get("Password")
            tok = entry.get("identitytoken") or entry.get("IdentityToken")
            if user is not None and pw is not None:
                out[host] = ("basic", f"{user}:{pw}")
            elif entry.get("auth"):
                try:
                    dec = base64.b64decode(entry["auth"]).decode("utf-8")
                except (ValueError, TypeError):
                    continue
                if ":" in dec:
                    out[host] = ("basic", dec)
            elif tok:
                out[host] = ("bearer", tok)
        if out:
            return out
    return {}



def _normalize_start_ip(raw):
    val = (raw or "").strip().split("/", 1)[0]
    if not val:
        return None
    parts = val.split(".")
    if len(parts) == 2:
        val = f"{val}.0.2"
    elif len(parts) == 3:
        val = f"{val}.2"
    try:
        addr = ipaddress.IPv4Address(val)
    except ipaddress.AddressValueError:
        return None
    if (int(addr) & 0xff) == 0:
        addr = ipaddress.IPv4Address(int(addr) | 2)
    return str(addr)


def _derive_gateway_ip(start_ip):
    try:
        addr = ipaddress.IPv4Address(start_ip)
    except ipaddress.AddressValueError:
        return DEFAULT_GATEWAY_IP
    h = int(addr)
    cand = (h & 0xffffff00) | 1
    if cand == h:
        cand = (h & 0xffffff00) | 254
    return str(ipaddress.IPv4Address(cand))


def load_kbox_config(config_path=None):
    """Load YAML settings from ~/.config/kbox-config.yaml (no PyYAML required)."""
    cfg = {
        "start_ip": DEFAULT_START_IP,
        "gateway": "",
        "volumes_root": os.path.abspath(os.path.expanduser(DEFAULT_VOLUMES_ROOT)),
        # mounts:<handle>: {source, options} — exports this daemon mounts for its
        # whole lifetime. Published as external volumes under their handle name,
        # so a container gets one ONLY by naming that volume; nothing here reaches
        # a container that did not ask.
        "mounts": {},
        "config_path": "",
        # Storage layout. Empty means "under the state directory".
        "blobs_dir": "",
        "images_dir": "",
        "layers_dir": "",
        "manifests_dir": "",
        "images_driver": "hostfs",
    }
    eff = config_path or os.environ.get("KBOX_CONFIG") or os.path.expanduser(DEFAULT_CONFIG_PATH)
    cfg["config_path"] = eff
    if eff and os.path.isfile(eff):
        section = ""
        # The handle of the mount currently being described, e.g. "nfs://persist".
        # A quoted key may carry a colon of its own, so the generic split below
        # cannot be used for it.
        mount_handle = ""
        mount_indent = 0
        with open(eff, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.split("#", 1)[0]
                indented = line[:1] in (" ", "\t")
                stripped = line.strip()
                if not stripped or ":" not in stripped:
                    continue
                # A quoted key may contain the separator, as every nfs:// handle
                # does ("nfs://persist":) — so the closing quote, not the first
                # colon, decides where the key ends.
                if stripped[0] in ("'", '"'):
                    close = stripped.find(stripped[0], 1)
                    if close < 0:
                        continue
                    key = stripped[1:close]
                    rest = stripped[close + 1:].lstrip()
                    val = rest[1:] if rest.startswith(":") else ""
                    val = val.strip()
                else:
                    key, val = stripped.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                    val = val[1:-1]
                if section == "mounts":
                    # Depth, not just "indented": the handle sits one level under
                    # mounts: and its fields one deeper. `nfs://persist:` is a
                    # handle line, `source:`/`options:` are fields of it.
                    depth = (len(line) - len(line.lstrip(" \t"))) if indented else 0
                    if depth <= mount_indent or not mount_handle:
                        mount_handle = key
                        mount_indent = depth if indented else 0
                        cfg["mounts"][mount_handle] = {"source": "", "options": ""}
                        if val:
                            cfg["mounts"][mount_handle]["source"] = val
                    else:
                        entry = cfg["mounts"][mount_handle]
                        if key in ("source", "server"):
                            entry["source"] = val
                        elif key in ("options", "opts"):
                            entry["options"] = val
                        elif key in ("visible_at", "visible-at", "at", "path"):
                            # The guest path this export occupies inside a
                            # container. Bind sources under it are rewritten to
                            # the export, so a project's `./data:/app/data` and a
                            # named volume both land on the export — while a
                            # container that names nothing still gets nothing.
                            entry["visible_at"] = val
                        elif key in ("sub", "subpath", "sub_path"):
                            # The subtree of the export this guest path stands
                            # for: one box, one home. Relative binds inside a
                            # container resolve here, not at the export root,
                            # so two pods never share a home directory.
                            entry["sub"] = val.strip("/")
                    continue
                if not indented and not val:
                    section = key
                    continue
                if not indented:
                    section = ""
                if (section in ("", "network")) and key in ("start_ip", "start-ip"):
                    norm = _normalize_start_ip(val)
                    if norm:
                        cfg["start_ip"] = norm
                elif (section in ("", "network")) and key in ("gateway", "gateway_ip"):
                    try:
                        cfg["gateway"] = str(ipaddress.IPv4Address(val))
                    except ipaddress.AddressValueError:
                        pass
                elif (section in ("", "volumes")) and key in ("root", "volumes_root", "dir"):
                    if val:
                        cfg["volumes_root"] = os.path.abspath(os.path.expanduser(val))
                elif section == "volumes" and key in ("export", "volumes_export"):
                    # volumes.export: nfs:// handle to keep named volumes on the
                    # durable export instead of the pod's ephemeral disk.
                    if val:
                        cfg["volumes_export"] = val
                elif not section and key == "volumes_root" and val:
                    cfg["volumes_root"] = os.path.abspath(os.path.expanduser(val))
                elif section == "storage" and key in ("images_dir", "images-dir"):
                    if val:
                        cfg["images_dir"] = os.path.abspath(os.path.expanduser(val))
                elif section == "storage" and key in ("blobs_dir", "blobs-dir"):
                    if val:
                        cfg["blobs_dir"] = os.path.abspath(os.path.expanduser(val))
                elif section == "storage" and key in ("layers_dir", "layers-dir"):
                    if val:
                        cfg["layers_dir"] = os.path.abspath(os.path.expanduser(val))
                elif section == "storage" and key in ("manifests_dir", "manifests-dir"):
                    if val:
                        cfg["manifests_dir"] = os.path.abspath(os.path.expanduser(val))
                elif section == "storage" and key == "images":
                    cfg["images_driver"] = "hostfs" if val == "hostfs" else "copy"
                elif section == "storage" and key in ("ephemeral_root",
                                                      "ephemeral-root"):
                    # Where the daemon keeps a container's writable overlay
                    # layer; the builder reads it to snapshot a RUN step.
                    if val:
                        cfg["ephemeral_root"] = os.path.abspath(
                            os.path.expanduser(val))
    if not cfg["gateway"]:
        cfg["gateway"] = _derive_gateway_ip(cfg["start_ip"])
    return cfg


NFS_SCHEME = "nfs://"


class ContainerConfigError(Exception):
    """A request the Docker API answers with 400, not 500."""


def is_nfs_source(src):
    """True for a volume source that names a kbox-declared NFS export."""
    return isinstance(src, str) and src.startswith(NFS_SCHEME)


def split_bind_spec(spec):
    """Split docker short syntax SRC:DST[:MODE] into (src, dst, mode).

    The nfs: scheme name carries a colon of its own ("nfs://mounted_here/sub>x"),
    so a naive split on ':' would misread the handle as the source.
    """
    if not isinstance(spec, str):
        return None
    if spec.startswith(NFS_SCHEME):
        i = spec.find(":", len(NFS_SCHEME))
        if i < 0:
            return None
        src, rest = spec[:i], spec[i + 1:]
    else:
        parts = spec.split(":", 2)
        if len(parts) < 2:
            return None
        src, rest = parts[0], ":".join(parts[1:])
    if ":" in rest:
        dst, mode = rest.split(":", 1)
    else:
        dst, mode = rest, ""
    if not dst.startswith("/"):
        return None
    return src, dst, mode


def rfc3339(ts):
    if not ts or ts <= 0:
        return "0001-01-01T00:00:00Z"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class KboxRpcClient:
    """Thread-safe JSON-line RPC client talking to `kbox daemon` Unix socket."""

    def __init__(self, sock_path):
        self.sock_path = sock_path
        self.lock = threading.Lock()

    def call(self, payload):
        data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        # Separate connection per RPC so concurrent wait/start calls never block.
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.sock_path)
        try:
            s.sendall(data)
            buf = bytearray()
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
        finally:
            s.close()
        if not buf:
            raise RuntimeError("empty reply from kbox daemon")
        line = bytes(buf).split(b"\n", 1)[0].decode("utf-8")
        resp = json.loads(line)
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "kbox daemon error"))
        return resp


class EventBus:
    """Pub/sub event stream for Docker `/events`."""

    def __init__(self):
        self.lock = threading.Lock()
        self.subs = []

    def emit(self, typ, action, actor_id, attrs=None):
        ev = {
            "Type": typ,
            "Action": action,
            "Actor": {
                "ID": actor_id,
                "Attributes": attrs or {},
            },
            "scope": "local",
            "time": int(time.time()),
            "timeNano": time.time_ns(),
        }
        with self.lock:
            for q in list(self.subs):
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    pass

    def subscribe(self):
        q = queue.Queue(maxsize=256)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)


class ImageStore:
    """OCI image puller, layer cache, and metadata registry.

    Layout (each directory is configurable through the storage: section of
    kbox-config.yaml, and defaults to a subdirectory of the state dir):

      <blobs_dir>/<digest>.tar     downloaded layer blobs, as pulled
      <layers_dir>/<digest>/       unpacked layer trees, immutable
      <manifests_dir>/<id>.json    image -> ordered layer digests
      <images_dir>/<id>/rootfs     merged tree, only for storage.images=copy
    """

    def __init__(self, state_dir, rpc, config=None):
        cfg = config or {}
        self.state_dir = state_dir
        self.blobs_dir = cfg.get("blobs_dir") or os.path.join(state_dir, "blobs")
        self.layers_dir = cfg.get("layers_dir") or os.path.join(state_dir, "layers")
        self.images_dir = cfg.get("images_dir") or os.path.join(state_dir, "images")
        self.manifests_dir = cfg.get("manifests_dir") or os.path.join(state_dir, "manifests")
        self.images_driver = cfg.get("images_driver", "hostfs")
        self.tags_file = os.path.join(state_dir, "tags.json")
        for d in (self.blobs_dir, self.layers_dir, self.images_dir,
                  self.manifests_dir):
            os.makedirs(d, exist_ok=True)
        self.rpc = rpc
        self.lock = threading.Lock()
        # One lock per layer digest: concurrent pulls of a shared base image
        # must not extract the same layer into one staging tree.
        self._layer_locks = {}
        self.tags = {}
        # host[:port] pull-through caches tried before the upstream registry, in
        # order. The mirror answers /v2/<repo>/... exactly like a registry, so a
        # pull turns into one more registry the layer cache can be filled from.
        self.registry_mirrors = []
        # host -> ("basic", "user:pass") | ("bearer", token), loaded from a
        # docker config.json when one is configured. Empty means anonymous.
        self.registry_auth = {}
        self._sweep_partials()
        self._load_tags()

    def _sweep_partials(self):
        """Remove leftovers of an interrupted pull; nothing is resumable."""
        for d in (self.blobs_dir, self.layers_dir, self.images_dir,
                  self.manifests_dir):
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for name in entries:
                if not (name.endswith(".part") or name.endswith(".tmp")
                        or ".stage-" in name or ".tmp." in name):
                    continue
                path = os.path.join(d, name)
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    def _load_tags(self):
        if os.path.exists(self.tags_file):
            try:
                with open(self.tags_file, "r", encoding="utf-8") as f:
                    self.tags = json.load(f)
            except Exception:
                self.tags = {}

    def _save_tags(self):
        # Unique temp name: concurrent pulls register tags from several threads.
        tmp = "%s.%d.%d.tmp" % (self.tags_file, os.getpid(), threading.get_ident())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.tags, f, indent=2)
        os.replace(tmp, self.tags_file)

    @staticmethod
    def normalize_ref(name, tag=None):
        if ":" in name and "/" not in name.split(":", 1)[1]:
            repo, t = name.rsplit(":", 1)
        elif tag:
            repo, t = name, tag
        else:
            repo, t = name, "latest"
        return f"{repo}:{t}", repo, t

    def resolve(self, ref):
        with self.lock:
            if ref in self.tags:
                return self.tags[ref]
            norm, _, _ = self.normalize_ref(ref)
            if norm in self.tags:
                return self.tags[norm]
            # Try stripping docker.io/library/
            short = re.sub(r"^(docker\.io/)?(library/)?", "", norm)
            if short in self.tags:
                return self.tags[short]
            # Match by image ID prefix
            clean = ref.removeprefix("sha256:")
            if os.path.exists(self.manifest_path("sha256:" + clean)):
                return "sha256:" + clean
            for k, iid in self.tags.items():
                if iid == ref or iid.removeprefix("sha256:").startswith(clean):
                    return iid
        return None

    def tag(self, src, repo, tag=None):
        """Point repo:tag at the image src resolves to (docker tag)."""
        iid = self.resolve(src)
        if not iid:
            return None
        norm, _, _ = self.normalize_ref(repo, tag)
        with self.lock:
            self.tags[norm] = iid
            self._save_tags()
        return norm

    def get_meta(self, img_id):
        meta_path = os.path.join(self.images_dir, img_id.removeprefix("sha256:"), "meta.json")
        if not os.path.exists(meta_path):
            return None
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def ensure_imported(self, img_id, layers=None):
        short = img_id.removeprefix("sha256:")
        rootfs = os.path.join(self.images_dir, short, "rootfs")
        if layers is None:
            # The manifest is the source of truth: container create and other
            # paths import an image that was pulled earlier.
            cached = self.load_manifest(img_id) or {}
            layers = cached.get("layers") or None
        msg = {"op": "image_import", "id": short, "src": rootfs}
        if layers:
            # Overlay lowerdir order is top-first, the manifest is base-first.
            msg["layers"] = [self.layer_path(d) for d in reversed(layers)]
        self.rpc.call(msg)

    def commit_container(self, container_id, ephemeral_root):
        """Snapshot a container's writable layer as a new image layer.

        The daemon mounts every container's rootfs over an upper layer on the
        host, so the changed files are already on this filesystem and the
        snapshot is a translated copy, not a walk through the guest kernel.
        """
        upper = os.path.join(ephemeral_root, container_id, "upper")
        if not os.path.isdir(upper):
            raise BuildError("container %s has no writable layer at %s"
                             % (container_id, upper))
        digest = secrets.token_hex(32)
        dest = os.path.join(self.layers_dir, digest)
        stage = "%s.stage-%d" % (dest, os.getpid())
        shutil.rmtree(stage, ignore_errors=True)
        os.makedirs(stage, exist_ok=True)
        _copy_upper_tree(upper, stage)
        os.replace(stage, dest)
        return "sha256:" + digest

    def register_built_image(self, ref, layers, config):
        """Record a built image: manifest, metadata, and optionally a tag."""
        key = json.dumps({"layers": list(layers), "config": config},
                         sort_keys=True, separators=(",", ":"))
        img_id = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
        short = img_id.removeprefix("sha256:")
        dest = os.path.join(self.images_dir, short)
        os.makedirs(dest, exist_ok=True)
        meta = {
            "id": img_id,
            "created": int(time.time()),
            "size": 0,
            "architecture": self._target_arch(),
            "os": "linux",
            "config": config,
            "layers": list(layers),
        }
        self.save_manifest(img_id, meta)
        with open(os.path.join(dest, "meta.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        if ref:
            norm, _, _ = self.normalize_ref(ref)
            short_norm = re.sub(r"^(docker\.io/)?(library/)?", "", norm)
            with self.lock:
                self.tags[norm] = img_id
                self.tags[short_norm] = img_id
                self._save_tags()
        self.ensure_imported(img_id, layers)
        return img_id

    def list_images(self):
        res = []
        seen = {}
        with self.lock:
            items = list(self.tags.items())
        for ref, iid in items:
            if iid not in seen:
                meta = self.get_meta(iid)
                if not meta:
                    continue
                seen[iid] = {
                    "Id": iid,
                    "ParentId": "",
                    "RepoTags": [],
                    "RepoDigests": [],
                    "Created": meta.get("created", 0),
                    "Size": meta.get("size", 0),
                    "SharedSize": -1,
                    "VirtualSize": meta.get("size", 0),
                    "Labels": meta.get("config", {}).get("Labels") or {},
                    "Containers": -1,
                }
            if ref not in seen[iid]["RepoTags"]:
                seen[iid]["RepoTags"].append(ref)
        for v in seen.values():
            res.append(v)
        return res

    @staticmethod
    def _target_arch():
        m = platform.machine().lower()
        if m in ("aarch64", "arm64"):
            return "arm64"
        if m in ("x86_64", "amd64"):
            return "amd64"
        return m

    @staticmethod
    def _split_registry(repo):
        parts = repo.split("/")
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
            host = "registry-1.docker.io" if parts[0] == "docker.io" else parts[0]
            rest = "/".join(parts[1:])
            if host == "registry-1.docker.io" and "/" not in rest:
                rest = f"library/{rest}"
            return host, rest
        if "/" not in repo:
            return "registry-1.docker.io", f"library/{repo}"
        return "registry-1.docker.io", repo

    # Hosts that mean Docker Hub, whatever spelling the config used. A config
    # written by `docker login` keys it as index.docker.io, while pulls resolve
    # to registry-1.docker.io — without this the credential never matched.
    _HUB_HOSTS = {"index.docker.io", "registry-1.docker.io", "docker.io",
                  "registry.hub.docker.com"}

    def _auth_for(self, url):
        """Pick the stored credential whose registry host serves this URL."""
        if not self.registry_auth:
            return None
        netloc = urllib.parse.urlsplit(url).netloc
        if netloc in self.registry_auth:
            return self.registry_auth[netloc]
        is_hub = netloc in self._HUB_HOSTS
        for key, cred in self.registry_auth.items():
            khost = urllib.parse.urlsplit(
                key if "://" in key else "https://" + key
            ).netloc
            if khost and (khost == netloc or (is_hub and khost in self._HUB_HOSTS)):
                return cred
        return None

    def _http_get_with_auth(self, url, headers=None, token_cache=None):
        hdrs = dict(headers or {})
        cred = self._auth_for(url)
        if cred and not (token_cache and token_cache.get("token")):
            kind, value = cred
            # A registry that takes a username/password (ECR does, with
            # `AWS:<ecr-token>`) is answered before the OAuth2 dance: its 401
            # advertises `Basic realm=...` with no token endpoint, so trying the
            # credential first is both simpler and the only path that works.
            hdrs["Authorization"] = (
                "Basic " + base64.b64encode(value.encode("utf-8")).decode("ascii")
                if kind == "basic"
                else "Bearer " + value
            )
        if token_cache and token_cache.get("token"):
            hdrs["Authorization"] = f"Bearer {token_cache['token']}"
        req = urllib.request.Request(url, headers=hdrs)
        try:
            return self._open(req, timeout=30)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            www = e.headers.get("WWW-Authenticate", "")
            # A basic-auth registry has no realm to exchange: re-sending the same
            # credential would only repeat the 401, so fail here instead of
            # looping through a token endpoint that does not exist.
            if cred and cred[0] == "basic" and "basic" in www.lower():
                raise
            m_realm = re.search(r'realm="([^"]+)"', www)
            if not m_realm:
                raise
            params = {}
            for k in ("service", "scope"):
                mk = re.search(rf'{k}="([^"]+)"', www)
                if mk:
                    params[k] = mk.group(1)
            tok_url = m_realm.group(1)
            if params:
                tok_url += ("&" if "?" in tok_url else "?") + urllib.parse.urlencode(params)
            treq = urllib.request.Request(tok_url)
            with urllib.request.urlopen(treq, timeout=20) as tresp:
                tdata = json.loads(tresp.read().decode("utf-8"))
            tok = tdata.get("token") or tdata.get("access_token")
            if token_cache is not None:
                token_cache["token"] = tok
            hdrs["Authorization"] = f"Bearer {tok}"
            return self._open(urllib.request.Request(url, headers=hdrs), timeout=60)

    @staticmethod
    def _open(req, timeout):
        return _SAME_ORIGIN_OPENER.open(req, timeout=timeout)

    # ---- layer cache -----------------------------------------------------

    @staticmethod
    def digest_hex(digest):
        return digest.split(":", 1)[-1]

    def layer_path(self, digest):
        return os.path.join(self.layers_dir, self.digest_hex(digest))

    def blob_path(self, digest):
        return os.path.join(self.blobs_dir, self.digest_hex(digest) + ".tar")

    def _download_blob(self, url, token_cache, digest_hex):
        """Stream a layer blob to disk, verifying the digest on the way.

        The body is copied in 1 MiB chunks so peak memory stays constant: a
        1 GiB layer costs 1 MiB of RAM here, not 1 GiB.
        """
        final = os.path.join(self.blobs_dir, digest_hex + ".tar")
        part = final + ".part"
        h = hashlib.sha256()
        with self._http_get_with_auth(url, {}, token_cache) as r, \
                open(part, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        return part, final, h.hexdigest()

    @staticmethod
    def _set_xattr(path, name):
        # os.setxattr is absent where Python lacks xattr support; the layer is
        # then unpacked without markers, which only affects whiteout layers.
        setxattr = getattr(os, "setxattr", None)
        if setxattr is None:
            return
        try:
            setxattr(path, name, b"y")
        except OSError:
            pass

    @staticmethod
    def _set_owner(path, member):
        """Record the tar owner as the user.kbox.owner xattr that hostfs reads.

        The daemon is not root and cannot chown, so a file owned by uid 999 in
        the image is stored as its own uid with this marker instead.
        """
        setxattr = getattr(os, "setxattr", None)
        if setxattr is None or (member.uid == 0 and member.gid == 0):
            return
        try:
            setxattr(path, "user.kbox.owner",
                     ("%d:%d" % (member.uid, member.gid)).encode(),
                     follow_symlinks=False)
        except OSError:
            pass

    @staticmethod
    def _is_whiteout(path):
        getxattr = getattr(os, "getxattr", None)
        if getxattr is None:
            return False
        try:
            getxattr(path, "user.overlay.whiteout")
            return True
        except OSError:
            return False

    def _extract_layer(self, tar_path, dest_dir):
        """Unpack one layer, keeping whiteouts as overlay markers.

        A layer unpacked on its own cannot delete entries of the layers below
        it, so .wh. markers are preserved instead of applied: a whiteout
        becomes an empty file carrying user.overlay.whiteout, and
        .wh..wh..opq marks the directory with user.overlay.opaque. overlayfs
        understands both when the mount uses the userxattr option.
        """
        # Directory modes are applied last: a read-only directory (0555, as in
        # ca-certificates) must stay writable while its entries are created,
        # and the daemon is not root.
        dir_modes = []
        with tarfile.open(tar_path, mode="r:*") as tf:
            for m in tf:
                # Only a real "./" prefix is cosmetic; lstrip("./") would also
                # eat the dot of a root-level whiteout like ".wh.hostname".
                rel = m.name
                while rel.startswith("./"):
                    rel = rel[2:]
                rel = rel.lstrip("/")
                if not rel:
                    continue
                base = os.path.basename(rel)
                parent = os.path.join(dest_dir, os.path.dirname(rel))
                if base == ".wh..wh..opq":
                    os.makedirs(parent, exist_ok=True)
                    self._set_xattr(parent, "user.overlay.opaque")
                    continue
                if base.startswith(".wh."):
                    os.makedirs(parent, exist_ok=True)
                    target = os.path.join(parent, base[4:])
                    if os.path.lexists(target):
                        if os.path.isdir(target) and not os.path.islink(target):
                            shutil.rmtree(target)
                        else:
                            os.unlink(target)
                    try:
                        with open(target, "wb"):
                            pass
                        self._set_xattr(target, "user.overlay.whiteout")
                    except OSError:
                        pass
                    continue

                dest = os.path.normpath(os.path.join(dest_dir, rel))
                if not (dest == dest_dir or dest.startswith(dest_dir + os.sep)):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if m.isdir():
                    os.makedirs(dest, exist_ok=True)
                    dir_modes.append((dest, m.mode & 0o7777))
                    self._set_owner(dest, m)
                elif m.issym():
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    os.symlink(m.linkname, dest)
                elif m.islnk():
                    link_target = os.path.normpath(
                        os.path.join(dest_dir, m.linkname.lstrip("./")))
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    if os.path.exists(link_target):
                        os.link(link_target, dest)
                elif m.isreg():
                    if os.path.lexists(dest):
                        if os.path.isdir(dest) and not os.path.islink(dest):
                            shutil.rmtree(dest)
                        else:
                            os.unlink(dest)
                    src_f = tf.extractfile(m)
                    if src_f is not None:
                        with open(dest, "wb") as out_f:
                            shutil.copyfileobj(src_f, out_f, 1 << 20)
                        os.chmod(dest, m.mode & 0o7777)
                        self._set_owner(dest, m)
        for path, mode in reversed(dir_modes):
            try:
                os.chmod(path, mode)
            except OSError:
                pass

    def ensure_layer(self, digest, url, token_cache, progress_cb=None):
        """Make sure layers/<digest>/ exists; download and unpack if not.

        Returns (layer_dir, tar_size). The unpacked tree is published with a
        rename, so a reader never sees a half-extracted layer.

        Serialised per digest: `docker compose up` pulls every image of the
        stack at once, two services sharing a base image ask for the SAME
        digest in different threads, and both then extract into one staging
        directory and race for the same destination — the loser's rename fails
        with "Directory not empty" and the whole pull fails.
        """
        with self._layer_lock(digest):
            return self._ensure_layer_locked(digest, url, token_cache, progress_cb)

    def _layer_lock(self, digest):
        with self.lock:
            lock = self._layer_locks.get(digest)
            if lock is None:
                lock = threading.Lock()
                self._layer_locks[digest] = lock
            return lock

    def _ensure_layer_locked(self, digest, url, token_cache, progress_cb):
        hexdigest = self.digest_hex(digest)
        layer_dir = self.layer_path(digest)
        blob = self.blob_path(digest)
        if os.path.isdir(layer_dir):
            size = os.path.getsize(blob) if os.path.exists(blob) else 0
            return layer_dir, size

        if not os.path.exists(blob):
            part, final, got = self._download_blob(url, token_cache, hexdigest)
            if got != hexdigest:
                try:
                    os.unlink(part)
                except OSError:
                    pass
                raise RuntimeError(
                    f"layer {digest}: digest mismatch ({got})")
            os.replace(part, final)
        size = os.path.getsize(blob)

        # A per-thread staging name, so a second extractor of the same digest
        # can never write into the tree this one is publishing.
        stage = os.path.join(
            self.layers_dir,
            ".stage-%s-%d-%d" % (hexdigest[:16], os.getpid(),
                                 threading.get_ident()))
        shutil.rmtree(stage, ignore_errors=True)
        os.makedirs(stage, exist_ok=True)
        try:
            self._extract_layer(blob, stage)
            if os.path.isdir(layer_dir) and not os.path.islink(layer_dir):
                # Published by another thread or an earlier run while this one
                # was extracting; the layers are immutable, so theirs is fine.
                shutil.rmtree(stage, ignore_errors=True)
            else:
                os.replace(stage, layer_dir)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return layer_dir, size

    def _clear_path(self, path):
        if not os.path.lexists(path):
            return
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)

    def _assemble_merged(self, layers, rootfs):
        """Build the merged tree for storage.images=copy.

        Files are hardlinked from the layer cache where the filesystem allows
        it (so identical bytes are stored once) and copied otherwise. Whiteout
        markers delete the lower entry, opaque directories are cleared.
        """
        shutil.rmtree(rootfs, ignore_errors=True)
        os.makedirs(rootfs, exist_ok=True)
        for digest in layers:  # base first
            layer_dir = self.layer_path(digest)
            if not os.path.isdir(layer_dir):
                continue
            for root, dirs, files in os.walk(layer_dir):
                rel = os.path.relpath(root, layer_dir)
                dst_root = rootfs if rel == "." else os.path.join(rootfs, rel)
                os.makedirs(dst_root, exist_ok=True)
                try:
                    if os.getxattr(root, "user.overlay.opaque") is not None:
                        for name in os.listdir(dst_root):
                            self._clear_path(os.path.join(dst_root, name))
                except (OSError, AttributeError):
                    pass
                for name in dirs:
                    os.makedirs(os.path.join(dst_root, name), exist_ok=True)
                for name in files:
                    src = os.path.join(root, name)
                    dst = os.path.join(dst_root, name)
                    is_marker = (os.path.isfile(src) and not os.path.islink(src)
                                 and self._is_whiteout(src))
                    if is_marker:
                        self._clear_path(dst)
                        continue
                    self._clear_path(dst)
                    try:
                        os.link(src, dst)
                    except OSError:
                        shutil.copy2(src, dst, follow_symlinks=False)

    # ---- manifests -------------------------------------------------------

    def manifest_path(self, img_id):
        return os.path.join(self.manifests_dir,
                            self.digest_hex(img_id) + ".json")

    def load_manifest(self, img_id):
        path = self.manifest_path(img_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def save_manifest(self, img_id, meta):
        path = self.manifest_path(img_id)
        # A unique temp name per writer: two services of one compose stack pull
        # the same image at once, and a shared "path.tmp" makes one writer
        # rename a file the other has already moved.
        tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        os.replace(tmp, path)

    def _registry_bases(self, registry, path_repo):
        """Every base URL a pull may resolve the image from, in order.

        Mirrors first: a pull-through cache in front of Docker Hub means the
        install fetches a public image once for the whole team instead of once
        per pod. The upstream registry stays last, so a cold or unreachable
        mirror degrades the pull rather than breaking it — the same
        pull-through-with-fallback contract dockerd's registry-mirrors has.
        """
        bases = []
        for mirror in self.registry_mirrors:
            host = mirror.split("://", 1)[-1].rstrip("/")
            if host:
                bases.append(f"http://{host}/v2/{path_repo}")
        scheme = "http" if registry.startswith("localhost") or registry.startswith("127.") else "https"
        bases.append(f"{scheme}://{registry}/v2/{path_repo}")
        return bases

    def pull(self, from_image, tag="latest", progress_cb=None):
        norm, repo, tag = self.normalize_ref(from_image, tag)
        short_norm = re.sub(r"^(docker\.io/)?(library/)?", "", norm)
        registry, path_repo = self._split_registry(repo)
        token_cache = {}
        accept = ", ".join([
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ])

        if progress_cb:
            progress_cb({"status": f"Pulling from {path_repo}", "id": tag})

        last_err = None
        for base in self._registry_bases(registry, path_repo):
            try:
                with self._http_get_with_auth(f"{base}/manifests/{tag}", {"Accept": accept}, token_cache) as r:
                    manifest = json.loads(r.read().decode("utf-8"))
                break
            except (urllib.error.URLError, OSError, ValueError) as err:
                last_err = err
                token_cache = {}
        else:
            raise last_err if last_err else RuntimeError(f"no registry could serve {repo}:{tag}")

        # Handle manifest list / OCI index
        if "manifests" in manifest:
            arch = self._target_arch()
            chosen = None
            for m in manifest["manifests"]:
                plat = m.get("platform", {})
                if plat.get("os") == "linux" and plat.get("architecture") == arch:
                    chosen = m["digest"]
                    break
            if not chosen and manifest["manifests"]:
                chosen = manifest["manifests"][0]["digest"]
            for cand in self._registry_bases(registry, path_repo):
                try:
                    with self._http_get_with_auth(f"{cand}/manifests/{chosen}", {"Accept": accept}, token_cache) as r:
                        manifest = json.loads(r.read().decode("utf-8"))
                    base = cand
                    break
                except (urllib.error.URLError, OSError, ValueError):
                    token_cache = {}

        cfg_digest = manifest["config"]["digest"]
        with self._http_get_with_auth(f"{base}/blobs/{cfg_digest}", {}, token_cache) as r:
            cfg_bytes = r.read()
        cfg_json = json.loads(cfg_bytes.decode("utf-8"))
        img_id = "sha256:" + hashlib.sha256(cfg_bytes).hexdigest()
        short_id = img_id.removeprefix("sha256:")
        dest_dir = os.path.join(self.images_dir, short_id)
        rootfs = os.path.join(dest_dir, "rootfs")

        # Digests never change for a finished image, so a manifest decides the
        # layer list. ensure_layer is a no-op for an unpacked layer and repairs
        # a missing one from the cached blob, without touching the network.
        cached = self.load_manifest(img_id)
        digests = []
        if cached and cached.get("layers"):
            digests = cached["layers"]
        else:
            digests = [layer["digest"] for layer in manifest.get("layers", [])]

        layers = []
        total_size = 0
        for ldig in digests:
            if progress_cb:
                progress_cb({"status": "Pulling fs layer", "id": ldig[7:19]})
            size = None
            layer_err = None
            for cand in self._registry_bases(registry, path_repo):
                try:
                    _, size = self.ensure_layer(ldig, f"{cand}/blobs/{ldig}",
                                                token_cache, progress_cb)
                    break
                except (urllib.error.URLError, OSError, RuntimeError) as err:
                    layer_err = err
                    continue
            if size is None:
                raise layer_err if layer_err else RuntimeError(f"layer {ldig}: no registry could serve it")
            if progress_cb:
                progress_cb({"status": "Extracting", "id": ldig[7:19]})
            total_size += size
            layers.append(ldig)

        meta = {
            "id": img_id,
            "created": int(time.time()),
            "size": total_size,
            "architecture": cfg_json.get("architecture", self._target_arch()),
            "os": cfg_json.get("os", "linux"),
            "config": cfg_json.get("config", {}),
            "layers": layers,
        }
        self.save_manifest(img_id, meta)

        os.makedirs(dest_dir, exist_ok=True)
        if self.images_driver != "hostfs":
            # storage.images=copy needs one merged tree for the daemon to copy
            # into the guest; hostfs mounts the layers themselves and skips it.
            if not os.path.isdir(rootfs):
                self._assemble_merged(layers, rootfs)
        if not os.path.exists(os.path.join(dest_dir, "meta.json")):
            with open(os.path.join(dest_dir, "meta.json"), "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

        with self.lock:
            self.tags[norm] = img_id
            self.tags[short_norm] = img_id
            self._save_tags()

        self.ensure_imported(img_id, layers)
        if progress_cb:
            progress_cb({"status": f"Status: Downloaded newer image for {short_norm}"})
        return img_id

    def import_dir_as_image(self, ref, src_dir, config=None):
        norm, _, _ = self.normalize_ref(ref)
        short_norm = re.sub(r"^(docker\.io/)?(library/)?", "", norm)
        img_id = "sha256:" + hashlib.sha256(norm.encode()).hexdigest()
        short_id = img_id.removeprefix("sha256:")
        dest_dir = os.path.join(self.images_dir, short_id)
        rootfs = os.path.join(dest_dir, "rootfs")
        if not os.path.exists(rootfs):
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copytree(src_dir, rootfs, symlinks=True)
        meta = {
            "id": img_id,
            "created": int(time.time()),
            "size": 0,
            "architecture": self._target_arch(),
            "os": "linux",
            "config": config or {},
        }
        with open(os.path.join(dest_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        with self.lock:
            self.tags[norm] = img_id
            self.tags[short_norm] = img_id
            self._save_tags()
        self.ensure_imported(img_id)
        return img_id


# Same default the daemon uses; both sides must name one directory.
DEFAULT_EPHEMERAL_ROOT = "/tmp/.kboxd/ephemeral"


class BuildError(Exception):
    """A build step that failed; the message goes to the client as is."""


def _xattr_get(path, name):
    try:
        return os.getxattr(path, name, follow_symlinks=False)
    except (OSError, AttributeError):
        return None


def _xattr_set(path, name):
    try:
        os.setxattr(path, name, b"y", follow_symlinks=False)
    except (OSError, AttributeError):
        pass


def _write_whiteout(path):
    """Mark a deleted entry the way the layer unpacker does.

    overlayfs reads a deletion from a lower layer as an empty file carrying
    user.overlay.whiteout, which is exactly what _extract_layer produces for a
    .wh. marker in a pulled layer, so a committed layer and a pulled one are
    interchangeable.
    """
    try:
        with open(path, "wb"):
            pass
        _xattr_set(path, "user.overlay.whiteout")
    except OSError:
        pass


def _copy_upper_tree(src, dst):
    """Turn a container's writable overlay layer into an image layer.

    The upper layer records a deletion as a character device 0/0 and an opaque
    directory as a user.overlay.opaque xattr; a layer that will sit below the
    next mount has to carry both in the form overlayfs recognises there.
    """
    st = os.lstat(src)
    if stat.S_ISCHR(st.st_mode) and st.st_rdev == 0:
        _write_whiteout(dst)
        return
    if stat.S_ISLNK(st.st_mode):
        os.symlink(os.readlink(src), dst)
        return
    if stat.S_ISDIR(st.st_mode):
        os.makedirs(dst, exist_ok=True)
        if _xattr_get(src, "user.overlay.opaque") is not None:
            _xattr_set(dst, "user.overlay.opaque")
        for name in os.listdir(src):
            _copy_upper_tree(os.path.join(src, name), os.path.join(dst, name))
        os.chmod(dst, stat.S_IMODE(st.st_mode) | stat.S_IWUSR | stat.S_IXUSR)
        return
    if stat.S_ISREG(st.st_mode):
        shutil.copyfile(src, dst)
        os.chmod(dst, stat.S_IMODE(st.st_mode))
        return
    # A socket or a fifo carries no filesystem content.


def _layer_whiteout(path):
    return _xattr_get(path, "user.overlay.whiteout") is not None


def _apply_layer_to(src, dst):
    """Overlay one layer directory onto a plain tree, whiteouts included."""
    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(dst, name)
        if name == ".wh..wh..opq":
            continue
        if name.startswith(".wh."):
            victim = os.path.join(dst, name[4:])
            if os.path.isdir(victim) and not os.path.islink(victim):
                shutil.rmtree(victim, ignore_errors=True)
            elif os.path.lexists(victim):
                os.unlink(victim)
            continue
        st = os.lstat(s)
        if stat.S_ISREG(st.st_mode) and _layer_whiteout(s):
            victim = d
            if os.path.isdir(victim) and not os.path.islink(victim):
                shutil.rmtree(victim, ignore_errors=True)
            elif os.path.lexists(victim):
                os.unlink(victim)
            continue
        if stat.S_ISDIR(st.st_mode):
            os.makedirs(d, exist_ok=True)
            _apply_layer_to(s, d)
            continue
        if os.path.lexists(d):
            if os.path.isdir(d) and not os.path.islink(d):
                shutil.rmtree(d, ignore_errors=True)
            else:
                os.unlink(d)
        if stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(s), d)
        elif stat.S_ISREG(st.st_mode):
            shutil.copyfile(s, d)
            os.chmod(d, stat.S_IMODE(st.st_mode))


def _parse_dockerfile(text):
    """Instructions of a Dockerfile, continuations joined, comments dropped."""
    joined = []
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1].strip() + " "
            continue
        buf += line
        joined.append(buf.strip())
        buf = ""
    if buf.strip():
        joined.append(buf.strip())
    out = []
    for line in joined:
        parts = line.split(None, 1)
        out.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return out


def _json_or_shell(arg):
    arg = arg.strip()
    if arg.startswith("["):
        try:
            val = json.loads(arg)
            if isinstance(val, list):
                return [str(v) for v in val]
        except ValueError:
            pass
    return None


def _demux_container_log(data):
    """Container output carries 8-byte frame headers; the build shows text."""
    out = bytearray()
    i = 0
    total = len(data)
    while i + 8 <= total:
        size = struct.unpack(">I", data[i + 4:i + 8])[0]
        if size > total - i - 8:
            break
        out += data[i + 8:i + 8 + size]
        i += 8 + size
    if not out and data:
        return data.decode("utf-8", "replace")
    return out.decode("utf-8", "replace")


class ImageBuilder:
    """The classic builder: every instruction becomes a layer of one image.

    BuildKit ships its own daemon and is out of reach here; this executes the
    same Dockerfile one step at a time against the kbox daemon and snapshots the
    container's writable layer after each step that can change files.
    """

    def __init__(self, engine, progress=None, buildargs=None):
        self.eng = engine
        self.store = engine.images
        self.progress = progress or (lambda _obj: None)
        self.buildargs = dict(buildargs or {})
        self.ephemeral_root = getattr(engine, "ephemeral_root",
                                      DEFAULT_EPHEMERAL_ROOT)
        self.stages = {}
        self.stage_list = []
        self.shell = ["/bin/sh", "-c"]

    def build(self, context_dir, dockerfile, tag):
        steps = _parse_dockerfile(dockerfile)
        if not steps:
            raise BuildError("the Dockerfile is empty")
        stage = None
        for ins, arg in steps:
            if ins == "FROM":
                stage = self._from(arg, context_dir)
                continue
            if stage is None:
                raise BuildError("the Dockerfile does not start with FROM")
            self.progress({"stream": "%s %s\n" % (ins, arg)})
            self._step(stage, ins, arg, context_dir)
        if stage is None:
            raise BuildError("the Dockerfile does not start with FROM")
        img_id = self.store.register_built_image(tag, stage["layers"],
                                                 stage["config"])
        if tag:
            self.progress({"stream": "Successfully tagged %s\n" % tag})
        self.progress({"aux": {"ID": img_id}})
        self._cleanup()
        return img_id

    def _cleanup(self):
        for stage in self.stage_list:
            tree = stage.get("_merged")
            if tree:
                shutil.rmtree(tree, ignore_errors=True)

    def _from(self, arg, context_dir):
        argv = [a for a in shlex.split(arg) if not a.startswith("--")]
        if not argv:
            raise BuildError("FROM without an image")
        ref = argv[0]
        name = None
        if len(argv) >= 3 and argv[1].upper() == "AS":
            name = argv[2].lower()
        base = self.stages.get(ref.lower())
        if base is not None:
            layers = list(base["layers"])
            config = dict(base["config"])
        else:
            iid = self.store.resolve(ref)
            if not iid:
                self.progress({"status": "Pulling %s" % ref})
                iid = self.store.pull(ref)
            meta = self.store.get_meta(iid) or {}
            manifest = self.store.load_manifest(iid) or {}
            layers = list(manifest.get("layers") or meta.get("layers") or [])
            config = dict(meta.get("config") or {})
            # A build stage starts from the filesystem, not the entrypoint:
            # carrying the parent's CMD would run it in every later step.
            config.pop("Cmd", None)
            config.pop("Entrypoint", None)
        stage = {"layers": layers, "config": config, "name": name,
                 "_merged": None}
        self.stage_list.append(stage)
        if name:
            self.stages[name] = stage
        self.stages[str(len(self.stage_list))] = stage
        return stage

    def _replace_vars(self, text, stage):
        def sub(match):
            key = match.group(1) or match.group(2)
            if key in self.buildargs:
                return self.buildargs[key]
            env = self._env_map(stage["config"]).get(key)
            return env if env is not None else match.group(0)

        return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                      sub, text)

    @staticmethod
    def _env_map(config):
        out = {}
        for item in config.get("Env") or []:
            key, _, val = item.partition("=")
            out[key] = val
        return out

    def _set_env(self, config, key, val):
        env = [e for e in (config.get("Env") or [])
               if e.partition("=")[0] != key]
        env.append("%s=%s" % (key, val))
        config["Env"] = env

    def _step(self, stage, ins, arg, context_dir):
        config = stage["config"]
        if ins == "ENV":
            for part in shlex.split(arg):
                key, sep, val = part.partition("=")
                if not sep:
                    key, _, val = arg.partition(" ")
                    self._set_env(config, key, val.strip())
                    break
                self._set_env(config, key, self._replace_vars(val, stage))
            return
        if ins == "ARG":
            for part in shlex.split(arg):
                key, sep, val = part.partition("=")
                if key and sep and key not in self.buildargs:
                    self.buildargs[key] = self._replace_vars(val, stage)
            return
        if ins == "WORKDIR":
            path = self._replace_vars(arg.strip(), stage)
            workdir = path if path.startswith("/") else os.path.join(
                config.get("WorkingDir") or "/", path)
            config["WorkingDir"] = os.path.normpath(workdir)
            self._mkdir_layer(stage, config["WorkingDir"])
            return
        if ins == "RUN":
            cmd = self._replace_vars(arg, stage)
            self._run(stage, cmd)
            return
        if ins in ("COPY", "ADD"):
            self._copy(stage, arg, context_dir, extract=(ins == "ADD"))
            return
        if ins == "USER":
            config["User"] = self._replace_vars(arg.strip(), stage)
            return
        if ins in ("CMD", "ENTRYPOINT"):
            val = _json_or_shell(arg)
            if val is None:
                val = [self.shell[0], self.shell[1], arg] if self.shell[1] \
                    else [self.shell[0], "-c", arg]
            config["Cmd" if ins == "CMD" else "Entrypoint"] = val
            return
        if ins == "SHELL":
            val = _json_or_shell(arg) or []
            if val:
                self.shell = val
            return
        if ins == "EXPOSE":
            ports = config.setdefault("ExposedPorts", {})
            for port in arg.split():
                port = port.split("/")[0]
                ports["%s/tcp" % port] = {}
            return
        if ins in ("LABEL", "MAINTAINER"):
            labels = config.setdefault("Labels", {})
            if ins == "MAINTAINER":
                labels["maintainer"] = arg.strip()
                return
            for part in shlex.split(arg):
                key, sep, val = part.partition("=")
                if sep:
                    labels[key] = self._replace_vars(val, stage)
            return
        if ins == "VOLUME":
            vols = config.setdefault("Volumes", {})
            val = _json_or_shell(arg)
            for path in (val or arg.split()):
                vols[path] = {}
            return
        # HEALTHCHECK, STOPSIGNAL, ONBUILD and unknown instructions describe
        # runtime behaviour kbox does not model; they do not change files.

    def _stage_dir(self):
        path = os.path.join(self.store.state_dir,
                            "build-stage-" + secrets.token_hex(8))
        os.makedirs(path, exist_ok=True)
        return path

    def _commit_dir(self, stage_dir):
        digest = secrets.token_hex(32)
        dest = os.path.join(self.store.layers_dir, digest)
        os.replace(stage_dir, dest)
        return "sha256:" + digest

    def _mkdir_layer(self, stage, path):
        stage_dir = self._stage_dir()
        try:
            os.makedirs(os.path.join(stage_dir, path.lstrip("/")), exist_ok=True)
        except OSError as exc:
            shutil.rmtree(stage_dir, ignore_errors=True)
            raise BuildError("WORKDIR %s: %s" % (path, exc))
        stage["layers"].append(self._commit_dir(stage_dir))

    def _materialize(self, stage):
        if stage.get("_merged"):
            return stage["_merged"]
        tree = os.path.join(self.store.state_dir,
                            "build-tree-" + secrets.token_hex(8))
        os.makedirs(tree, exist_ok=True)
        for digest in stage["layers"]:
            _apply_layer_to(self.store.layer_path(digest), tree)
        stage["_merged"] = tree
        return tree

    def _copy(self, stage, arg, context_dir, extract=False):
        parts = shlex.split(self._replace_vars(arg, stage))
        flags = [p for p in parts if p.startswith("--")]
        rest = [p for p in parts if not p.startswith("--")]
        if len(rest) < 2:
            raise BuildError("COPY takes a source and a destination")
        sources, dest = rest[:-1], rest[-1]
        source_root = context_dir
        for flag in flags:
            if flag.startswith("--from="):
                base = self.stages.get(flag[len("--from="):].lower())
                if base is None:
                    raise BuildError("COPY --from=%s: no such stage" % flag)
                source_root = self._materialize(base)
        if not dest.startswith("/"):
            dest = os.path.join(stage["config"].get("WorkingDir") or "/", dest)
        dest = os.path.normpath(dest)
        into_dir = dest.endswith("/") or len(sources) > 1
        stage_dir = self._stage_dir()
        try:
            for src in sources:
                # A path from another stage is absolute inside that stage;
                # a context path is relative to the context directory.
                rel = src.lstrip("/") if source_root is not context_dir else src
                if any(ch in rel for ch in "*?["):
                    matches = sorted(glob.glob(os.path.join(source_root, rel)))
                    if not matches:
                        raise BuildError("COPY: %s matched nothing" % src)
                else:
                    path = os.path.join(source_root, rel)
                    if not os.path.exists(path):
                        raise BuildError("COPY: %s does not exist" % src)
                    matches = [path]
                for match in matches:
                    target_root = os.path.join(stage_dir, dest.lstrip("/"))
                    if extract and source_root is context_dir and \
                            tarfile.is_tarfile(match):
                        # ADD unpacks a local archive into the destination.
                        os.makedirs(target_root, exist_ok=True)
                        with tarfile.open(match) as tf:
                            try:
                                tf.extractall(target_root, filter="tar")
                            except TypeError:
                                tf.extractall(target_root)
                        continue
                    if os.path.isdir(match) and not os.path.islink(match):
                        # A directory copies its contents, not itself.
                        os.makedirs(target_root, exist_ok=True)
                        for name in os.listdir(match):
                            self._copy_entry(os.path.join(match, name),
                                             os.path.join(target_root, name))
                    elif into_dir or os.path.isdir(target_root):
                        os.makedirs(target_root, exist_ok=True)
                        self._copy_entry(match, os.path.join(
                            target_root, os.path.basename(match)))
                    else:
                        self._copy_entry(match, target_root)
        except Exception:
            shutil.rmtree(stage_dir, ignore_errors=True)
            raise
        stage["layers"].append(self._commit_dir(stage_dir))

    @staticmethod
    def _copy_entry(src, dst):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.isdir(src) and not os.path.islink(src):
            shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
        else:
            if os.path.lexists(dst):
                os.unlink(dst)
            if os.path.islink(src):
                os.symlink(os.readlink(src), dst)
            else:
                shutil.copy2(src, dst)

    def _run(self, stage, command):
        image_id = self.store.register_built_image(None, stage["layers"],
                                                   stage["config"])
        body = {
            "Image": image_id,
            "Cmd": [self.shell[0], "-c", command] if len(self.shell) > 1
            else list(self.shell) + [command],
            "WorkingDir": stage["config"].get("WorkingDir") or "/",
        }
        container = self.eng.create_container(None, body)
        self.eng.start_container(container)
        try:
            result = self.eng.rpc.call({"op": "container_wait",
                                        "id": container["id"]})
            code = int(result.get("exit_code", 0) or 0)
        except Exception as exc:
            code = 137
            self.progress({"stream": "wait failed: %s\n" % exc})
        output = ""
        log_path = container.get("log_path")
        if log_path and os.path.exists(log_path):
            try:
                with open(log_path, "rb") as fh:
                    output = _demux_container_log(fh.read())
            except OSError:
                output = ""
        if output:
            self.progress({"stream": output})
        if code != 0:
            self.eng.rpc.call({"op": "container_rm", "id": container["id"],
                               "force": True})
            raise BuildError("the command '/bin/sh -c %s' returned a non-zero "
                             "code: %d" % (command, code))
        layer = self.store.commit_container(container["id"], self.ephemeral_root)
        stage["layers"].append(layer)
        stage["_merged"] = None
        self.eng.rpc.call({"op": "container_rm", "id": container["id"],
                           "force": True})


class DockerEngineState:
    """In-memory state for containers, networks, and persistent volumes."""

    def __init__(self, rpc, state_dir, path_maps=None, config_path=None, config=None):
        self.rpc = rpc
        self.state_dir = state_dir
        self.path_maps = path_maps or []
        self.config = config if config is not None else load_kbox_config(config_path)
        self.ephemeral_root = self.config.get("ephemeral_root",
                                              DEFAULT_EPHEMERAL_ROOT)
        self.start_ip = self.config.get("start_ip", DEFAULT_START_IP)
        self.gateway_ip = self.config.get("gateway") or _derive_gateway_ip(self.start_ip)
        self.subnet_cidr = str(ipaddress.IPv4Network(f"{self.gateway_ip}/16", strict=False))
        self.events = EventBus()
        self.images = ImageStore(state_dir, rpc, config=self.config)
        self.lock = threading.Lock()
        self.containers = {}
        self.networks = {
            "kbox-bridge-default": {
                "Name": "bridge",
                "Id": "kbox-bridge-default",
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": "bridge",
                "EnableIPv6": False,
                "Internal": False,
                "Attachable": False,
                "Ingress": False,
                "IPAM": {
                    "Driver": "default",
                    "Options": None,
                    "Config": [{"Subnet": self.subnet_cidr, "Gateway": self.gateway_ip}],
                },
                "Options": {},
                "Labels": {},
            },
            "kbox-host-default": {
                "Name": "host",
                "Id": "kbox-host-default",
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": "host",
                "IPAM": {"Driver": "default", "Config": []},
                "Options": {},
                "Labels": {},
            },
            "kbox-none-default": {
                "Name": "none",
                "Id": "kbox-none-default",
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": "null",
                "IPAM": {"Driver": "default", "Config": []},
                "Options": {},
                "Labels": {},
            },
        }
        self.volumes = {}
        self.execs = {}
        vol_cfg = self.config.get("volumes_root")
        self.vol_root = os.path.abspath(os.path.expanduser(vol_cfg)) if vol_cfg else os.path.join(state_dir, "volumes")
        # Where named volumes keep their data. `volumes.export` names an nfs://
        # handle (declared under mounts:) to put project volumes on the durable
        # export instead of the pod's ephemeral disk.
        self.vol_export = (self.config.get("volumes_export") or "").strip()
        os.makedirs(self.vol_root, exist_ok=True)
        self._load_persisted_volumes()
        self.publish_declared_mounts()
        self._next_ephemeral_port = 20000

    @staticmethod
    def _validate_volume_name(vname):
        if (
            not vname
            or vname in (".", "..")
            or "/" in vname
            or "\\" in vname
            or "\0" in vname
        ):
            raise ValueError(f"invalid volume name: {vname!r}")
        return vname

    def _volume_meta_path(self, vname):
        return os.path.join(self.vol_root, vname, "meta.json")

    def _volume_data_dir(self, vname):
        # Named volumes are a project's durable state (a DB, a cache). With an
        # export configured they live ON it, so they survive the pod exactly like
        # /persist does; the daemon creates the subtree on the export when the
        # volume is first bound, and binds it into the container.
        if self.vol_export:
            return f"{self.vol_export.rstrip('/')}/{vname}/_data"
        return os.path.join(self.vol_root, vname, "_data")

    def _write_volume_meta(self, vname, vobj):
        meta_path = self._volume_meta_path(vname)
        # The index stays on local disk even when the data lives on the export:
        # metadata.db-like bookkeeping on a remote filesystem is slow and racy,
        # and entrypoint.sh already keeps dockerd's own index local for the same
        # reason. Only the volume's _data is remote.
        os.makedirs(os.path.dirname(meta_path), exist_ok=True)
        tmp_path = f"{meta_path}.tmp.{os.getpid()}.{threading.get_ident()}"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(vobj, f, indent=2, sort_keys=True)
        os.replace(tmp_path, meta_path)

    def _load_persisted_volumes(self):
        if not os.path.isdir(self.vol_root):
            return
        for entry in sorted(os.listdir(self.vol_root)):
            if entry.startswith("."):
                continue
            vdir = os.path.join(self.vol_root, entry)
            if not os.path.isdir(vdir):
                continue
            data_dir = os.path.join(vdir, "_data")
            meta_path = os.path.join(vdir, "meta.json")
            if not os.path.isdir(data_dir) and not os.path.isfile(meta_path):
                continue
            os.makedirs(data_dir, exist_ok=True)
            vobj = None
            if os.path.isfile(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        vobj = json.load(f)
                except Exception:
                    vobj = None
            if not isinstance(vobj, dict):
                vobj = {
                    "Name": entry,
                    "Driver": "local",
                    "Mountpoint": data_dir,
                    "CreatedAt": rfc3339(os.path.getctime(vdir)),
                    "Labels": {},
                    "Scope": "local",
                    "Options": {},
                }
            else:
                vobj["Name"] = vobj.get("Name") or entry
                vobj["Mountpoint"] = data_dir
                vobj.setdefault("Driver", "local")
                vobj.setdefault("Scope", "local")
                vobj.setdefault("Labels", {})
                vobj.setdefault("Options", {})
                vobj.setdefault("CreatedAt", rfc3339(time.time()))
            self.volumes[entry] = vobj

    def ensure_volume(self, vname, labels=None, options=None, service=None):
        # A derived nfs:// volume names a subtree of a declared export and may
        # contain slashes, so it is resolved before the name is validated.
        derived = self.nfs_volume(vname)
        if derived:
            return derived
        vname = self._validate_volume_name(vname)
        # A declared export is already published under this name by
        # publish_declared_mounts, and its Mountpoint is the nfs:// handle.
        # Creating a directory for it under vol_root would shadow the export with
        # an empty local dir: the container would write there, report success, and
        # nothing would reach the server.
        with self.lock:
            published = self.volumes.get(vname)
        if published and published.get("Driver") == "kbox-nfs":
            return dict(published)
        data_dir = self._volume_data_dir(vname)
        on_export = is_nfs_source(data_dir)
        if not on_export:
            os.makedirs(data_dir, exist_ok=True)
        with self.lock:
            existing = self.volumes.get(vname)
            if existing:
                vobj = dict(existing)
                vobj["Mountpoint"] = data_dir
                merged_labels = dict(vobj.get("Labels") or {})
                if labels:
                    merged_labels.update(labels)
                if service and "com.docker.compose.service" not in merged_labels:
                    merged_labels["com.docker.compose.service"] = service
                vobj["Labels"] = merged_labels
                if options:
                    opts = dict(vobj.get("Options") or {})
                    opts.update(options)
                    vobj["Options"] = opts
            else:
                merged_labels = dict(labels or {})
                if service and "com.docker.compose.service" not in merged_labels:
                    merged_labels["com.docker.compose.service"] = service
                vobj = {
                    "Name": vname,
                    "Driver": "kbox-nfs" if on_export else "local",
                    "Mountpoint": data_dir,
                    "CreatedAt": rfc3339(time.time()),
                    "Labels": merged_labels,
                    "Scope": "local",
                    "Options": dict(options or {}),
                }
            self.volumes[vname] = vobj
            self._write_volume_meta(vname, vobj)
            return dict(vobj)

    def remove_volume(self, vname):
        vname = self._validate_volume_name(vname)
        with self.lock:
            existed = self.volumes.pop(vname, None) is not None
        vdir = os.path.join(self.vol_root, vname)
        if os.path.isdir(vdir):
            shutil.rmtree(vdir, ignore_errors=True)
            existed = True
        return existed

    def publish_declared_mounts(self):
        """Expose each config-declared export as a volume named after its handle.

        The export is mounted for the daemon's whole lifetime — that is the
        config's job. Handing it to containers is NOT: a volume exists, and a
        container receives it only by naming it (compose: `external: true` with
        `name: "nfs://persist"`). So a project's compose file gets exactly the
        subdirectories it asks for, while the system stack that runs the agent
        asks for the whole handle and gets the whole export.

        Published volumes carry Mountpoint=nfs://... and Driver=kbox-nfs so the
        mount path is never confused with a local directory: a container that
        binds one must go through the daemon's NFS path, not a host path.

        A mount that declares `sub:` is published TWICE: the bare handle, and
        handle/sub. The second is the name the system stack asks for (this pod's
        own home), and compose only accepts an external volume it finds in this
        list — so publishing the bare handle alone left the agent stack failing
        with "external volume not found".
        """
        for handle, entry in (self.config.get("mounts") or {}).items():
            if not handle or not entry.get("source"):
                continue
            names = [handle]
            sub = (entry.get("sub") or "").strip("/")
            if sub:
                names.append(f"{handle}/{sub}")
            for name in names:
                with self.lock:
                    existing = self.volumes.get(name)
                    vobj = dict(existing or {})
                    vobj["Name"] = name
                    vobj["Driver"] = "kbox-nfs"
                    vobj["Mountpoint"] = name
                    vobj.setdefault("CreatedAt", rfc3339(time.time()))
                    vobj.setdefault("Labels", {})
                    vobj.setdefault("Scope", "local")
                    vobj["Options"] = {
                        **(vobj.get("Options") or {}),
                        "source": entry.get("source", ""),
                        "options": entry.get("options", ""),
                    }
                    self.volumes[name] = vobj

    def nfs_volume(self, name):
        """A synthetic volume for an nfs:// source, or None.

        A compose file may name a SUBTREE of a declared export
        (`name: "nfs://persist/persists/<pod>"`), which is how the agent gets its
        own home while project containers get only their subdirectories. Such a
        name is never published — it is derived — so `GET /volumes/<name>` and
        `ensure_volume` must resolve it here, or compose rejects the external
        volume as non-existent and never starts the service.
        """
        if not is_nfs_source(name):
            return None
        base = name[len("nfs://"):].split("/", 1)[0]
        declared = (self.config.get("mounts") or {}).get("nfs://" + base)
        # Only a DECLARED export can be handed out. Anything else is a typo in a
        # compose file, and answering it with an empty volume would turn that typo
        # into a container writing to nowhere while reporting success.
        if not declared:
            return None
        return {
            "Name": name,
            "Driver": "kbox-nfs",
            "Mountpoint": name,
            "CreatedAt": rfc3339(time.time()),
            "Labels": {},
            "Scope": "local",
            "Options": {"source": (declared or {}).get("source", ""),
                        "options": (declared or {}).get("options", "")},
        }

    def resolve_volume(self, name):
        """A declared or derived NFS volume by name, else None."""
        with self.lock:
            known = self.volumes.get(name)
        if known:
            return dict(known)
        return self.nfs_volume(name)

    def export_for_guest_path(self, path):
        """The nfs:// handle an absolute guest path belongs to, or None.

        An export declares `visible_at: /persist`, meaning that inside a container
        it looks like a plain directory. Anything a compose file binds from under
        it is really a subtree of the export, so the source has to become the
        handle — otherwise the daemon would look for a host path that does not
        exist. This is what makes `./docker/data-monitor:/root/.local/solidus`
        work unchanged: the agent lives on /persist, so its relative binds already
        point there.
        """
        if not path.startswith("/"):
            return None
        for handle, entry in (self.config.get("mounts") or {}).items():
            root = (entry.get("visible_at") or "").rstrip("/")
            if not root:
                continue
            if path != root and not path.startswith(root + "/"):
                continue
            base = handle
            sub = (entry.get("sub") or "").strip("/")
            if sub:
                base = f"{handle}/{sub}"
            if path == root:
                return base
            return base + path[len(root):]
        return None

    def map_host_path(self, p):
        for src_prefix, dst_prefix in self.path_maps:
            if p == src_prefix:
                return dst_prefix
            if p.startswith(src_prefix.rstrip("/") + "/"):
                return dst_prefix.rstrip("/") + p[len(src_prefix.rstrip("/")):]
        return p

    def prepare_bind_source(self, src):
        """Create a missing `-v` source directory, as the Docker daemon does.

        Compose files such as `./data:/data` depend on it for the first start.
        The long `--mount` form stays strict, because Docker rejects a missing
        source there and callers rely on that error.
        """
        if os.path.exists(src):
            return src
        try:
            os.makedirs(src, exist_ok=True)
        except OSError as err:
            raise ContainerConfigError(
                f"error while creating mount source path '{src}': {err.strerror}"
            ) from None
        return src

    def _alloc_ephemeral_port(self):
        p = self._next_ephemeral_port
        self._next_ephemeral_port += 1
        return p

    def find_network(self, key):
        with self.lock:
            if key in self.networks:
                return self.networks[key]
            for n in self.networks.values():
                if n["Name"] == key or n["Id"].startswith(key):
                    return n
        return None

    def find_container(self, key):
        key = key.lstrip("/")
        with self.lock:
            if key in self.containers:
                return self.containers[key]
            for c in self.containers.values():
                if c["name"] == key or c["id"].startswith(key):
                    return c
        return None

    def refresh_container(self, c):
        try:
            st = self.rpc.call({"op": "container_inspect", "id": c["id"]})
            c["status"] = st.get("state", c["status"])
            c["pid"] = st.get("pid", 0)
            c["exit_code"] = st.get("exit_code", 0)
            c["ip"] = st.get("ip", c.get("ip", ""))
            c["started_at"] = st.get("started_at", c.get("started_at", 0))
            c["finished_at"] = st.get("finished_at", c.get("finished_at", 0))
            if st.get("log_path"):
                c["log_path"] = st["log_path"]
            if c["status"] != "running" and c.get("health_stop") is not None:
                c["health_stop"].set()
        except Exception:
            pass

    @staticmethod
    def match_filters(item_id, name, labels, status, filters_json):
        if not filters_json:
            return True
        if isinstance(filters_json, str):
            filters = json.loads(filters_json)
        else:
            filters = filters_json

        if "id" in filters:
            vals = filters["id"]
            if not any(item_id.startswith(v) or item_id == v for v in vals):
                return False
        if "name" in filters:
            vals = filters["name"]
            if not any(v in name or name == v.lstrip("/") for v in vals):
                return False
        if "status" in filters:
            vals = filters["status"]
            if status not in vals:
                return False
        if "label" in filters:
            for expr in filters["label"]:
                if "=" in expr:
                    k, v = expr.split("=", 1)
                    if labels.get(k) != v:
                        return False
                else:
                    if expr not in labels:
                        return False
        return True

    def create_container(self, name, body):
        image_ref = body.get("Image", "")
        img_id = self.images.resolve(image_ref)
        if not img_id:
            raise KeyError(f"No such image: {image_ref}")
        meta = self.images.get_meta(img_id) or {}
        img_cfg = meta.get("config") or {}
        self.images.ensure_imported(img_id)

        cid = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        cname = (name or "").lstrip("/") or f"kbox-{cid[:12]}"

        img_ep = img_cfg.get("Entrypoint") or []
        img_cmd = img_cfg.get("Cmd") or []
        if body.get("Entrypoint") is not None:
            ep = body["Entrypoint"]
            cmd = body.get("Cmd") if body.get("Cmd") is not None else []
        else:
            ep = img_ep
            cmd = body.get("Cmd") if body.get("Cmd") is not None else img_cmd
        full_cmd = list(ep) + list(cmd)
        if not full_cmd:
            full_cmd = ["/bin/sh"]

        # Merge env vars
        env_map = {}
        env_order = []
        for item in list(img_cfg.get("Env") or []) + list(body.get("Env") or []):
            k = item.split("=", 1)[0]
            if k not in env_map:
                env_order.append(k)
            env_map[k] = item
        hostname = body.get("Hostname") or cname
        # Docker sets these for the container process when neither the image nor the
        # request does. HOME matters: an entrypoint that writes $HOME/.aws/credentials
        # (the lambda-sim containers) put the file in "/" instead of /root, and the
        # SDK, which reads the passwd home, found no credentials.
        for k, v in (("HOME", "/root"), ("HOSTNAME", hostname)):
            if k not in env_map:
                env_order.append(k)
                env_map[k] = f"{k}={v}"
        merged_env = [env_map[k] for k in env_order]

        workdir = body.get("WorkingDir") or img_cfg.get("WorkingDir") or "/"
        labels = dict(img_cfg.get("Labels") or {})
        labels.update(body.get("Labels") or {})

        host_cfg = body.get("HostConfig") or {}
        service_name = labels.get("com.docker.compose.service") or cname
        binds = []
        mounts_json = []
        for b in host_cfg.get("Binds") or []:
            parsed = split_bind_spec(b)
            if parsed is None:
                continue
            raw_src, dst, mode_str = parsed
            ro_flag = "ro" in mode_str.split(",")
            mode = ":ro" if ro_flag else ""
            if is_nfs_source(raw_src):
                # Hard-coded scheme name: the volume lives on an NFS export
                # declared in the kbox config, and the daemon bind-mounts the
                # requested subtree. Passed through verbatim.
                mounts_json.append({
                    "Type": "bind",
                    "Source": raw_src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
                binds.append(f"{raw_src}:{dst}{mode}")
                continue
            if not raw_src.startswith("/"):
                vobj = self.ensure_volume(raw_src, service=service_name)
                src = vobj["Mountpoint"]
                # A config-declared export is published as a volume whose
                # Mountpoint IS its nfs:// handle. Binding the mountpoint would
                # hand the guest a host path that does not exist; the handle must
                # travel through the daemon's NFS path instead, exactly as a
                # direct `-v nfs://persist:/persist` does. That is what lets a
                # PROJECT compose file name the volume and receive only the
                # subdirectory it asked for.
                if is_nfs_source(src):
                    mounts_json.append({
                        "Type": "bind",
                        "Source": src,
                        "Destination": dst,
                        "Mode": "ro" if ro_flag else "rw",
                        "RW": not ro_flag,
                    })
                    binds.append(f"{src}:{dst}{mode}")
                    continue
                mounts_json.append({
                    "Type": "volume",
                    "Name": raw_src,
                    "Source": src,
                    "Destination": dst,
                    "Driver": "local",
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            else:
                # A bind from under a declared export is a subtree of that export
                # (`/persist/...`), not a host path: the agent lives on the
                # export, so its relative binds resolve there. Translating first
                # is what makes a project compose file work unchanged.
                as_export = self.export_for_guest_path(raw_src)
                if as_export:
                    mounts_json.append({
                        "Type": "bind",
                        "Source": as_export,
                        "Destination": dst,
                        "Mode": "ro" if ro_flag else "rw",
                        "RW": not ro_flag,
                    })
                    binds.append(f"{as_export}:{dst}{mode}")
                    continue
                src = self.prepare_bind_source(self.map_host_path(raw_src))
                mounts_json.append({
                    "Type": "bind",
                    "Source": src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            binds.append(f"{src}:{dst}{mode}")

        for m in host_cfg.get("Mounts") or []:
            mtype = m.get("Type", "bind")
            src = m.get("Source", "")
            dst = m.get("Target", "")
            if not dst:
                continue
            ro_flag = bool(m.get("ReadOnly"))
            ro = ":ro" if ro_flag else ""
            if is_nfs_source(src):
                mounts_json.append({
                    "Type": "bind",
                    "Source": src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
                binds.append(f"{src}:{dst}{ro}")
                continue
            if mtype == "volume":
                vname = src or secrets.token_hex(8)
                vobj = self.ensure_volume(vname, service=service_name)
                src = vobj["Mountpoint"]
                # Same rule as the short form: a declared export is a volume
                # whose mountpoint is its nfs:// handle, and the handle has to go
                # through the daemon's NFS path, never be treated as a host path.
                if is_nfs_source(src):
                    mounts_json.append({
                        "Type": "bind",
                        "Source": src,
                        "Destination": dst,
                        "Mode": "ro" if ro_flag else "rw",
                        "RW": not ro_flag,
                    })
                    binds.append(f"{src}:{dst}{ro}")
                    continue
                mounts_json.append({
                    "Type": "volume",
                    "Name": vname,
                    "Source": src,
                    "Destination": dst,
                    "Driver": "local",
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            else:
                src = self.map_host_path(src)
                # Docker rejects a missing --mount source at create time. The
                # daemon would otherwise start a container whose mount points
                # at nothing, and every access would answer ENOENT.
                if not os.path.exists(src):
                    raise ContainerConfigError(
                        'invalid mount config for type "bind": '
                        f"bind source path does not exist: {src}"
                    )
                mounts_json.append({
                    "Type": "bind",
                    "Source": src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            binds.append(f"{src}:{dst}{ro}")

        ports = []
        port_bindings = host_cfg.get("PortBindings") or {}
        mapped_ports_json = {}
        for cport_proto, blist in port_bindings.items():
            cport_str = cport_proto.split("/")[0]
            try:
                cport = int(cport_str)
            except ValueError:
                continue
            out_list = []
            for entry in blist or [{"HostIp": "0.0.0.0", "HostPort": ""}]:
                e = entry or {}
                hip = (e.get("HostIp") or "").strip() or "0.0.0.0"
                hp_str = str(e.get("HostPort") or "").strip()
                hp = (
                    int(hp_str)
                    if hp_str.isdigit() and int(hp_str) > 0
                    else self._alloc_ephemeral_port()
                )
                ports.append(f"{hip}:{hp}:{cport}")
                out_list.append({"HostIp": hip, "HostPort": str(hp)})
            mapped_ports_json[cport_proto] = out_list
        exposed_ports = dict(body.get("ExposedPorts") or {})

        # Collect DNS aliases from NetworkingConfig.EndpointsConfig and Compose labels
        aliases = [cname, cid[:12], hostname]
        svc_label = labels.get("com.docker.compose.service")
        if svc_label and svc_label not in aliases:
            aliases.append(svc_label)

        net_cfg = (body.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}
        attached_nets = {}
        for net_name, ep_cfg in net_cfg.items():
            for al in (ep_cfg or {}).get("Aliases") or []:
                if al and al not in aliases:
                    aliases.append(al)
            attached_nets[net_name] = dict(ep_cfg or {})
        if not attached_nets:
            nmode = host_cfg.get("NetworkMode") or "bridge"
            attached_nets[nmode] = {}

        rpc_resp = self.rpc.call({
            "op": "container_create",
            "id": cid,
            "image": img_id.removeprefix("sha256:"),
            "name": cname,
            "hostname": hostname,
            "workdir": workdir,
            "cmd": full_cmd,
            "env": merged_env,
            "binds": binds,
            "aliases": aliases,
            "ports": ports,
            "host_net": host_cfg.get("NetworkMode") == "host",
            "mem_limit": int(host_cfg.get("Memory") or 0),
        })

        hc = body.get("Healthcheck")
        if hc is None:
            hc = img_cfg.get("Healthcheck")
        hc_test = hc.get("Test") if isinstance(hc, dict) else None
        if not isinstance(hc_test, list) or not hc_test or hc_test == ["NONE"]:
            hc = None

        rec = {
            "id": cid,
            "name": cname,
            "image": image_ref,
            "image_id": img_id,
            "created": int(time.time()),
            "started_at": 0,
            "finished_at": 0,
            "status": "created",
            "pid": 0,
            "exit_code": 0,
            "ip": rpc_resp.get("ip", ""),
            "gateway": rpc_resp.get("gateway", self.gateway_ip),
            "log_path": rpc_resp.get("log_path", f"/tmp/kboxd-logs/{cid}.log"),
            "cmd": cmd,
            "entrypoint": ep,
            "full_cmd": full_cmd,
            "env": merged_env,
            "workdir": workdir,
            "hostname": hostname,
            "labels": labels,
            "tty": bool(body.get("Tty", False)),
            "open_stdin": bool(body.get("OpenStdin", False)),
            "host_config": host_cfg,
            "port_bindings": mapped_ports_json,
            "exposed_ports": exposed_ports,
            "networks": attached_nets,
            "mounts_json": mounts_json,
            "healthcheck": hc,
            "health": None,
            "health_stop": threading.Event(),
            # Set once start_container() has seen the run begin. A /wait that
            # arrives before it must not ask the daemon: a container that has
            # not started yet reads as exited there, and the client would stop
            # following output while the container keeps running.
            "run_ev": threading.Event(),
        }
        with self.lock:
            self.containers[cid] = rec
        self.events.emit("container", "create", cid, {**labels, "name": cname, "image": image_ref})
        return rec

    def _watch_exit(self, c, gen=None):
        try:
            w = self.rpc.call({"op": "container_wait", "id": c["id"]})
            ec = w.get("exit_code", 0)
        except Exception:
            ec = 137
        # A watcher started by an older run must not overwrite the state of a
        # container that has been restarted since (compose restarts containers
        # in place, and the previous wait returns at that point).
        if gen is not None and c.get("gen") != gen:
            return
        c["status"] = "exited"
        c["exit_code"] = ec
        c["finished_at"] = int(time.time())
        if c.get("health_stop") is not None:
            c["health_stop"].set()
        self.events.emit(
            "container", "die", c["id"],
            {**c["labels"], "name": c["name"], "exitCode": str(ec)},
        )

    @staticmethod
    def _read_multiplexed_output(log_path, limit=4096):
        out = bytearray()
        try:
            with open(log_path, "rb") as f:
                while len(out) < limit:
                    hdr = f.read(8)
                    if len(hdr) < 8:
                        break
                    slen = struct.unpack(">I", hdr[4:8])[0]
                    payload = f.read(slen)
                    out.extend(payload[: max(0, limit - len(out))])
                    if len(payload) < slen:
                        break
        except OSError:
            return ""
        return out.decode("utf-8", errors="replace")

    @staticmethod
    def _healthcheck_cmd(test):
        if not test:
            return None
        kind = test[0]
        if kind == "CMD":
            return list(test[1:])
        if kind == "CMD-SHELL" and len(test) >= 2:
            return ["/bin/sh", "-c", test[1]]
        return list(test)

    def _run_healthcheck_once(self, c, cmd, timeout_s):
        start_ts = time.time()
        ec = 1
        out = ""
        eid = None
        try:
            e = self.create_exec(c, {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True})
            eid = e["id"]
            self.start_exec(e)
            if not e["done_ev"].wait(timeout=timeout_s):
                ec = 1
                out = "healthcheck timed out"
            else:
                ec = int(e.get("exit_code", 1))
                out = self._read_multiplexed_output(e["log_path"])
        except Exception as exc:
            ec = 1
            out = str(exc)
        finally:
            if eid:
                with self.lock:
                    self.execs.pop(eid, None)
        end_ts = time.time()
        return {
            "Start": rfc3339(start_ts),
            "End": rfc3339(end_ts),
            "ExitCode": ec,
            "Output": out,
        }

    def _watch_health(self, c):
        hc = c.get("healthcheck") or {}
        cmd = self._healthcheck_cmd(hc.get("Test") or [])
        if not cmd:
            return
        interval_s = max(0.2, int(hc.get("Interval") or 30_000_000_000) / 1e9)
        timeout_s = max(0.5, int(hc.get("Timeout") or 30_000_000_000) / 1e9)
        retries = max(1, int(hc.get("Retries") or 3))
        start_period_s = max(0.0, int(hc.get("StartPeriod") or 0) / 1e9)
        stop_ev = c["health_stop"]
        started_monotonic = time.monotonic()

        # Run an initial probe promptly so `service_healthy` converges without waiting
        # a full interval when a container comes up fast, then follow configured Interval.
        if stop_ev.wait(timeout=min(1.0, interval_s)):
            return

        while not stop_ev.is_set():
            self.refresh_container(c)
            if c["status"] != "running":
                break
            entry = self._run_healthcheck_once(c, cmd, timeout_s)
            if stop_ev.is_set() or c["status"] != "running":
                break

            with self.lock:
                h = c.get("health")
                if h is None:
                    break
                prev_status = h["Status"]
                log = list(h.get("Log") or [])
                log.append(entry)
                if len(log) > 5:
                    log = log[-5:]
                h["Log"] = log
                if entry["ExitCode"] == 0:
                    h["FailingStreak"] = 0
                    h["Status"] = "healthy"
                else:
                    in_start_period = (time.monotonic() - started_monotonic) < start_period_s
                    if not in_start_period:
                        h["FailingStreak"] = int(h.get("FailingStreak", 0)) + 1
                        if h["FailingStreak"] >= retries:
                            h["Status"] = "unhealthy"
                new_status = h["Status"]

            if new_status != prev_status and new_status in ("healthy", "unhealthy"):
                self.events.emit(
                    "container", f"health_status: {new_status}", c["id"],
                    {**c["labels"], "name": c["name"]},
                )

            wait_s = min(interval_s, 2.0) if new_status == "starting" else interval_s
            if stop_ev.wait(timeout=wait_s):
                break

    def _ensure_mount_sources(self, c):
        """Recreate volume directories that disappeared while the container
        existed. Docker keeps named volumes across container restarts, so a
        missing directory must not turn into a broken mount (the guest then
        dies with "mkdir: cannot create directory ...: No such file or
        directory" and exit 127).
        """
        for m in c.get("mounts_json") or []:
            src = m.get("Source")
            if not src or not os.path.isabs(src):
                continue
            try:
                owned = os.path.commonpath(
                    [os.path.abspath(src), self.vol_root]
                ) == self.vol_root
            except ValueError:
                owned = False
            if owned:
                os.makedirs(src, exist_ok=True)

    def start_container(self, c):
        self._ensure_mount_sources(c)
        resp = self.rpc.call({"op": "container_start", "id": c["id"]})
        c["status"] = "running"
        c["pid"] = resp.get("pid", 0)
        c["ip"] = resp.get("ip", c.get("ip", ""))
        c["started_at"] = int(time.time())
        # A restart must not report the previous run's exit status.
        c["exit_code"] = 0
        c["finished_at"] = 0
        c["gen"] = c.get("gen", 0) + 1
        gen = c["gen"]
        c["run_ev"].set()
        if c.get("healthcheck"):
            c["health"] = {"Status": "starting", "FailingStreak": 0, "Log": []}
            c["health_stop"].clear()
            ht = threading.Thread(target=self._watch_health, args=(c,), daemon=True)
            ht.start()
        self.events.emit("container", "start", c["id"], {**c["labels"], "name": c["name"]})
        t = threading.Thread(target=self._watch_exit, args=(c, gen), daemon=True)
        t.start()

    def copy_into(self, c, dest_dir, blob):
        """Unpack a tar into a path inside a container.

        The container's rootfs lives in the LKL guest, so the archive cannot be
        written from here. Two cases, because Docker allows both:
          - running container: stream it into a tar over the FIFO-backed stdin
            that `docker exec -i` already uses;
          - created, not yet started: hand it to the daemon, which has no rootfs
            to write into yet (the overlay is built at start) and applies it
            right after that.
        Buildx takes the second path to install its buildkitd config, so this
        is what makes `docker build` possible at all.
        """
        self.refresh_container(c)
        if c["status"] != "running":
            # The daemon reads the archive from a file: it and this shim share
            # one filesystem, and the RPC is line-delimited JSON.
            tmp = os.path.join(self.state_dir, "cp-" + secrets.token_hex(8) + ".tar")
            with open(tmp, "wb") as fh:
                fh.write(blob)
            try:
                self.rpc.call({
                    "op": "container_put_archive",
                    "id": c["id"],
                    "dest": dest_dir,
                    "path": tmp,
                })
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return None

        fifo = os.path.join(self.state_dir, "cp-" + secrets.token_hex(8))
        try:
            os.unlink(fifo)
        except OSError:
            pass
        os.mkfifo(fifo)

        rec = self.create_exec(c, {
            "Cmd": ["/bin/sh", "-c",
                    'cd "$1" && tar -xf -', "sh", dest_dir],
            "AttachStdin": True,
            "AttachStdout": True,
            "AttachStderr": True,
        })
        rec["stdin_path"] = fifo
        self.start_exec(rec)

        def feed():
            try:
                with open(fifo, "wb") as w:
                    w.write(blob)
            except Exception as exc:
                print(f"[dockerd] copy_into feed failed: {exc}", file=sys.stderr)
            finally:
                try:
                    os.unlink(fifo)
                except OSError:
                    pass

        threading.Thread(target=feed, daemon=True).start()
        return rec

    def create_exec(self, c, body):
        self.refresh_container(c)
        if c["status"] != "running":
            raise RuntimeError(f"Container {c['id']} is not running")
        eid = secrets.token_hex(32)
        cmd = body.get("Cmd") or ["/bin/sh"]
        env = body.get("Env") or []
        workdir = body.get("WorkingDir") or ""
        tty = bool(body.get("Tty", False))
        rec = {
            "id": eid,
            "container_id": c["id"],
            "cmd": cmd,
            "env": env,
            "workdir": workdir,
            "tty": tty,
            "attach_stdin": bool(body.get("AttachStdin", False)),
            "attach_stdout": bool(body.get("AttachStdout", True)),
            "attach_stderr": bool(body.get("AttachStderr", True)),
            "running": False,
            "exited": False,
            "exit_code": 0,
            "pid": 0,
            "log_path": f"/tmp/kboxd-logs/exec-{eid}.log",
            "stdin_path": "",
            "done_ev": threading.Event(),
        }
        with self.lock:
            self.execs[eid] = rec
        return rec

    def _watch_exec_exit(self, e):
        try:
            w = self.rpc.call({"op": "exec_wait", "exec_id": e["id"]})
            ec = w.get("exit_code", 0)
        except Exception:
            ec = 137
        e["exit_code"] = ec
        e["running"] = False
        e["exited"] = True
        e["done_ev"].set()

    def start_exec(self, e):
        payload = {
            "op": "exec_start",
            "exec_id": e["id"],
            "container_id": e["container_id"],
            "cmd": e["cmd"],
            "env": e["env"],
            "workdir": e["workdir"],
        }
        if e.get("stdin_path"):
            payload["stdin_path"] = e["stdin_path"]
        resp = self.rpc.call(payload)
        e["pid"] = resp.get("pid", 0)
        e["log_path"] = resp.get("log_path", e["log_path"])
        e["running"] = True
        t = threading.Thread(target=self._watch_exec_exit, args=(e,), daemon=True)
        t.start()

    def exec_inspect_json(self, e):
        return {
            "CanRemove": False,
            "DetachKeys": "",
            "ID": e["id"],
            "Running": e["running"],
            "ExitCode": e["exit_code"],
            "ProcessConfig": {
                "privileged": False,
                "user": "",
                "tty": e["tty"],
                "entrypoint": e["cmd"][0] if e["cmd"] else "/bin/sh",
                "arguments": e["cmd"][1:] if len(e["cmd"]) > 1 else [],
            },
            "OpenStdin": False,
            "OpenStderr": e["attach_stderr"],
            "OpenStdout": e["attach_stdout"],
            "ContainerID": e["container_id"],
            "Pid": e["pid"],
        }

    def container_inspect_json(self, c):
        self.refresh_container(c)
        running = c["status"] == "running"
        gw = c.get("gateway") or self.gateway_ip
        nets_out = {}
        for nname, ep in c["networks"].items():
            net_obj = self.find_network(nname)
            nid = net_obj["Id"] if net_obj else "kbox-bridge-default"
            nets_out[nname] = {
                "IPAMConfig": ep.get("IPAMConfig"),
                "Links": ep.get("Links"),
                "Aliases": ep.get("Aliases") or [c["name"], c["id"][:12]],
                "NetworkID": nid,
                "EndpointID": hashlib.sha256(f"{nid}:{c['id']}".encode()).hexdigest()[:16],
                "Gateway": gw,
                "IPAddress": c["ip"],
                "IPPrefixLen": 32,
                "IPv6Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "MacAddress": "02:42:ac:12:00:02",
            }
        ports_ns = {}
        for cport_proto, blist in c["port_bindings"].items():
            ports_ns[cport_proto] = blist

        state_out = {
            "Status": c["status"],
            "Running": running,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": c["pid"] if running else 0,
            "ExitCode": c["exit_code"],
            "Error": "",
            "StartedAt": rfc3339(c["started_at"]),
            "FinishedAt": rfc3339(c["finished_at"]),
        }
        if c.get("health") is not None:
            with self.lock:
                h = c["health"]
                state_out["Health"] = {
                    "Status": h["Status"],
                    "FailingStreak": h["FailingStreak"],
                    "Log": list(h["Log"]),
                }

        cfg_out = {
            "Hostname": c["hostname"],
            "Domainname": "",
            "User": "",
            "AttachStdin": False,
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": c["tty"],
            "OpenStdin": c["open_stdin"],
            "StdinOnce": False,
            "Env": c["env"],
            "Cmd": c["cmd"],
            "Image": c["image"],
            "WorkingDir": c["workdir"],
            "Entrypoint": c["entrypoint"],
            "ExposedPorts": c.get("exposed_ports") or {},
            "Labels": c["labels"],
        }
        if c.get("healthcheck") is not None:
            cfg_out["Healthcheck"] = c["healthcheck"]

        return {
            "Id": c["id"],
            "Created": rfc3339(c["created"]),
            "Path": c["full_cmd"][0] if c["full_cmd"] else "/bin/sh",
            "Args": c["full_cmd"][1:] if len(c["full_cmd"]) > 1 else [],
            "State": state_out,
            "Image": c["image_id"],
            "Name": "/" + c["name"],
            "RestartCount": 0,
            "Driver": "overlay2",
            "Platform": "linux",
            "Mounts": c["mounts_json"],
            "Config": cfg_out,
            "HostConfig": {
                **c["host_config"],
                "PortBindings": c["port_bindings"],
            },
            "NetworkSettings": {
                "Bridge": "br0",
                "Gateway": gw,
                "IPAddress": c["ip"],
                "IPPrefixLen": 32,
                "Ports": ports_ns,
                "Networks": nets_out,
            },
        }


class DockerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"Docker/{SERVER_VERSION}"

    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            # On a unix socket client_address is a path string (often empty), not
            # the (host, port) pair address_string() expects.
            peer = self.address_string() if isinstance(self.client_address, tuple) else "unix"
            sys.stderr.write(f"[dockerd] {peer} - {fmt % args}\n")

    def _send_docker_headers(self):
        self.send_header("Api-Version", API_VERSION)
        self.send_header("Min-Api-Version", MIN_API_VERSION)
        self.send_header("Ostype", "linux")
        self.send_header("Docker-Experimental", "false")
        self.send_header("Server", f"Docker/{SERVER_VERSION} (linux)")

    def send_json(self, code, obj):
        body = (json.dumps(obj) + "\n").encode("utf-8")
        self.send_response(code)
        self._send_docker_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_empty(self, code, ctype="text/plain"):
        self.send_response(code)
        self._send_docker_headers()
        if code not in (204, 304):
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", "0")
        self.end_headers()

    def _begin_chunked(self, code, ctype):
        self.send_response(code)
        self._send_docker_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _write_chunk(self, data):
        if not data:
            return
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.wfile.write(f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()

    def _end_chunked(self):
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _read_body(self):
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            out = bytearray()
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                sz = int(line.strip().split(b";", 1)[0], 16)
                if sz == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                out.extend(self.rfile.read(sz))
                self.rfile.read(2)
            return bytes(out)
        cl = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(cl) if cl > 0 else b""

    def _read_json(self):
        raw = self._read_body()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _parse_url(self):
        u = urllib.parse.urlparse(self.path)
        clean_path = re.sub(r"^/v\d+\.\d+", "", u.path) or "/"
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        return clean_path, qs

    def do_HEAD(self):
        path, _ = self._parse_url()
        if path == "/_ping":
            self.send_response(200)
            self._send_docker_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "2")
            self.end_headers()
            return
        self.send_empty(404)

    def do_GET(self):
        eng = self.server.engine
        path, qs = self._parse_url()

        if path == "/_ping":
            self.send_response(200)
            self._send_docker_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        if path == "/version":
            arch = "arm64" if platform.machine().lower() in ("aarch64", "arm64") else "amd64"
            self.send_json(200, {
                "Platform": {"Name": "kbox LKL Engine"},
                "Components": [{"Name": "Engine", "Version": SERVER_VERSION, "Details": {"ApiVersion": API_VERSION, "Arch": arch, "Os": "linux"}}],
                "Version": SERVER_VERSION,
                "ApiVersion": API_VERSION,
                "MinAPIVersion": MIN_API_VERSION,
                "Os": "linux",
                "Arch": arch,
                "KernelVersion": "6.8.0-kbox",
            })
            return

        if path == "/info":
            arch = platform.machine()
            with eng.lock:
                total = len(eng.containers)
                running = sum(1 for c in eng.containers.values() if c["status"] == "running")
            self.send_json(200, {
                "ID": "kbox-single-lkl-engine",
                "Containers": total,
                "ContainersRunning": running,
                "ContainersPaused": 0,
                "ContainersStopped": total - running,
                "Images": len(eng.images.list_images()),
                "Driver": "overlay2",
                "OperatingSystem": "kbox LKL (single-kernel namespaces)",
                "OSType": "linux",
                "Architecture": arch,
                "KernelVersion": "6.8.0-kbox",
                "Name": "kboxd",
                "ServerVersion": SERVER_VERSION,
                "NCPU": 1,
                "MemTotal": 1024 * 1024 * 1024,
            })
            return

        if path == "/events":
            self._handle_events(qs)
            return

        if path == "/images/json":
            self.send_json(200, eng.images.list_images())
            return

        m = re.match(r"^/images/(.+)/json$", path)
        if m:
            ref = urllib.parse.unquote(m.group(1))
            iid = eng.images.resolve(ref)
            if not iid:
                self.send_json(404, {"message": f"No such image: {ref}"})
                return
            meta = eng.images.get_meta(iid) or {}
            tags = [k for k, v in eng.images.tags.items() if v == iid]
            self.send_json(200, {
                "Id": iid,
                "RepoTags": tags,
                "Created": rfc3339(meta.get("created", 0)),
                "Architecture": meta.get("architecture", "arm64"),
                "Os": "linux",
                "Size": meta.get("size", 0),
                "Config": meta.get("config", {}),
            })
            return

        if path == "/networks":
            filters = (qs.get("filters") or [None])[0]
            out = []
            with eng.lock:
                nets = list(eng.networks.values())
            for n in nets:
                if eng.match_filters(n["Id"], n["Name"], n.get("Labels") or {}, "", filters):
                    out.append(n)
            self.send_json(200, out)
            return

        m = re.match(r"^/networks/([^/]+)$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            if not n:
                self.send_json(404, {"message": "network not found"})
                return
            ncopy = dict(n)
            cdict = {}
            with eng.lock:
                clist = list(eng.containers.values())
            for c in clist:
                if n["Name"] in c["networks"] or n["Id"] in c["networks"]:
                    cdict[c["id"]] = {
                        "Name": c["name"],
                        "EndpointID": c["id"][:16],
                        "MacAddress": "02:42:ac:12:00:02",
                        "IPv4Address": f"{c['ip']}/16" if c.get("ip") else "",
                        "IPv6Address": "",
                    }
            ncopy["Containers"] = cdict
            self.send_json(200, ncopy)
            return

        if path == "/volumes":
            with eng.lock:
                vols = list(eng.volumes.values())
            self.send_json(200, {"Volumes": vols, "Warnings": []})
            return

        # The name is percent-decoded, and an nfs:// handle contains slashes of
        # its own, so the capture must allow them: `[^/]+` matched `nfs:` only
        # and every lookup of a declared export 404'd — which compose reads as a
        # missing external volume.
        m = re.match(r"^/volumes/(.+)$", path)
        if m:
            vname = urllib.parse.unquote(m.group(1))
            v = eng.resolve_volume(vname)
            if not v:
                self.send_json(404, {"message": f"no such volume: {vname}"})
            else:
                self.send_json(200, v)
            return

        if path == "/containers/json":
            show_all = (qs.get("all") or ["0"])[0] in ("1", "true", "True")
            filters = (qs.get("filters") or [None])[0]
            out = []
            with eng.lock:
                clist = list(eng.containers.values())
            for c in clist:
                eng.refresh_container(c)
                if not show_all and c["status"] != "running" and not filters:
                    continue
                if not eng.match_filters(c["id"], c["name"], c["labels"], c["status"], filters):
                    continue
                ports_list = []
                for cport_proto, blist in c["port_bindings"].items():
                    cp = int(cport_proto.split("/")[0])
                    for b in blist:
                        ports_list.append({
                            "IP": b.get("HostIp", "0.0.0.0"),
                            "PrivatePort": cp,
                            "PublicPort": int(b.get("HostPort", 0)),
                            "Type": "tcp",
                        })
                if c["status"] == "running":
                    h = c.get("health")
                    ps_status = f"Up ({h['Status']})" if h else "Up"
                elif c["status"] == "created":
                    ps_status = "Created"
                else:
                    ps_status = f"Exited ({c['exit_code']})"
                out.append({
                    "Id": c["id"],
                    "Names": ["/" + c["name"]],
                    "Image": c["image"],
                    "ImageID": c["image_id"],
                    "Command": " ".join(c["full_cmd"]),
                    "Created": c["created"],
                    "Ports": ports_list,
                    "Labels": c["labels"],
                    "State": c["status"],
                    "Status": ps_status,
                    "HostConfig": {"NetworkMode": next(iter(c["networks"]), "bridge")},
                    "NetworkSettings": {"Networks": {k: {"IPAddress": c["ip"]} for k in c["networks"]}},
                    "Mounts": c["mounts_json"],
                })
            self.send_json(200, out)
            return

        m = re.match(r"^/containers/([^/]+)/json$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            # Report live state: compose polls inspect while waiting for a
            # container to exit, and a cached "running" hides the exit.
            eng.refresh_container(c)
            self.send_json(200, eng.container_inspect_json(c))
            return

        m = re.match(r"^/containers/([^/]+)/logs$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            self._handle_logs(c, qs)
            return

        m = re.match(r"^/exec/([^/]+)/json$", path)
        if m:
            eid = urllib.parse.unquote(m.group(1))
            with eng.lock:
                e = eng.execs.get(eid)
            if not e:
                self.send_json(404, {"message": f"No such exec instance: {eid}"})
                return
            self.send_json(200, eng.exec_inspect_json(e))
            return

        self.send_json(404, {"message": f"page not found: {path}"})

    def do_POST(self):
        eng = self.server.engine
        path, qs = self._parse_url()

        if path == "/build":
            self._handle_build(qs)
            return

        if path == "/images/create":
            from_img = (qs.get("fromImage") or [""])[0]
            tag = (qs.get("tag") or ["latest"])[0]
            if not from_img:
                self.send_json(400, {"message": "fromImage required"})
                return
            self._begin_chunked(200, "application/json")
            try:
                def emit_p(obj):
                    self._write_chunk(json.dumps(obj) + "\n")
                eng.images.pull(from_img, tag, progress_cb=emit_p)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._write_chunk(json.dumps({"error": str(e), "errorDetail": {"message": str(e)}}) + "\n")
            self._end_chunked()
            return

        m = re.match(r"^/images/(.+)/tag$", path)
        if m:
            src = urllib.parse.unquote(m.group(1))
            repo = (qs.get("repo") or [""])[0]
            tag = (qs.get("tag") or [None])[0]
            if not repo:
                self.send_json(400, {"message": "repo required"})
                return
            if eng.images.tag(src, repo, tag) is None:
                self.send_json(404, {"message": f"No such image: {src}"})
                return
            self.send_empty(201)
            return

        if path == "/networks/create":
            body = self._read_json()
            name = body.get("Name", "")
            nid = hashlib.sha256((name + secrets.token_hex(8)).encode()).hexdigest()
            net = {
                "Name": name,
                "Id": nid,
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": body.get("Driver") or "bridge",
                "EnableIPv6": False,
                "Internal": bool(body.get("Internal", False)),
                "Attachable": bool(body.get("Attachable", True)),
                "Ingress": False,
                "IPAM": {
                    "Driver": "default",
                    "Options": None,
                    "Config": [{"Subnet": eng.subnet_cidr, "Gateway": eng.gateway_ip}],
                },
                "Options": body.get("Options") or {},
                "Labels": body.get("Labels") or {},
            }
            with eng.lock:
                eng.networks[nid] = net
            eng.events.emit("network", "create", nid, {"name": name, "type": net["Driver"]})
            self.send_json(201, {"Id": nid, "Warning": ""})
            return

        m = re.match(r"^/networks/([^/]+)/connect$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            body = self._read_json()
            c = eng.find_container(body.get("Container", ""))
            if not n or not c:
                self.send_json(404, {"message": "network or container not found"})
                return
            ep_cfg = body.get("EndpointConfig") or {}
            c["networks"][n["Name"]] = ep_cfg
            for al in ep_cfg.get("Aliases") or []:
                if c.get("ip"):
                    eng.rpc.call({"op": "dns_set", "name": al, "ip": c["ip"]})
            self.send_empty(200)
            return

        m = re.match(r"^/networks/([^/]+)/disconnect$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            body = self._read_json()
            c = eng.find_container(body.get("Container", ""))
            if n and c:
                c["networks"].pop(n["Name"], None)
            self.send_empty(200)
            return

        if path == "/volumes/create":
            body = self._read_json()
            vname = body.get("Name") or secrets.token_hex(16)
            try:
                vobj = eng.ensure_volume(
                    vname,
                    labels=body.get("Labels") or {},
                    options=body.get("DriverOpts") or {},
                )
            except ValueError as e:
                self.send_json(400, {"message": str(e)})
                return
            self.send_json(201, vobj)
            return

        if path == "/containers/create":
            body = self._read_json()
            cname = (qs.get("name") or [""])[0]
            try:
                rec = eng.create_container(cname, body)
                self.send_json(201, {"Id": rec["id"], "Warnings": []})
            except ContainerConfigError as e:
                self.send_json(400, {"message": str(e)})
            except KeyError as e:
                self.send_json(404, {"message": str(e)})
            except Exception as e:
                self.send_json(500, {"message": str(e)})
            return

        m = re.match(r"^/containers/([^/]+)/start$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            try:
                eng.start_container(c)
                self.send_empty(204)
            except Exception as e:
                self.send_json(500, {"message": str(e)})
            return

        m = re.match(r"^/containers/([^/]+)/stop$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            timeout = int((qs.get("t") or ["10"])[0] or "10")
            eng.refresh_container(c)
            if c["status"] != "running":
                self.send_empty(304)
                return
            eng.rpc.call({"op": "container_stop", "id": c["id"], "timeout": timeout})
            if c.get("health_stop") is not None:
                c["health_stop"].set()
            eng.refresh_container(c)
            eng.events.emit("container", "stop", c["id"], {**c["labels"], "name": c["name"]})
            self.send_empty(204)
            return

        m = re.match(r"^/containers/([^/]+)/restart$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            timeout = int((qs.get("t") or ["10"])[0] or "10")
            try:
                eng.refresh_container(c)
                if c["status"] == "running":
                    eng.rpc.call({"op": "container_stop", "id": c["id"], "timeout": timeout})
                    if c.get("health_stop") is not None:
                        c["health_stop"].set()
                    eng.refresh_container(c)
                    eng.events.emit("container", "stop", c["id"], {**c["labels"], "name": c["name"]})
                eng.start_container(c)
                eng.events.emit("container", "restart", c["id"], {**c["labels"], "name": c["name"]})
                self.send_empty(204)
            except Exception as e:
                self.send_json(500, {"message": str(e)})
            return

        m = re.match(r"^/containers/([^/]+)/kill$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            eng.rpc.call({"op": "container_kill", "id": c["id"], "signal": 9})
            self.send_empty(204)
            return

        m = re.match(r"^/containers/([^/]+)/rename$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            new_name = ((qs.get("name") or [""])[0] or "").lstrip("/")
            if not new_name:
                self.send_json(400, {"message": "name query parameter is required"})
                return
            with eng.lock:
                for other in eng.containers.values():
                    if other["id"] != c["id"] and other["name"] == new_name:
                        self.send_json(409, {"message": f"Conflict. The container name \"/{new_name}\" is already in use"})
                        return
                old_name = c["name"]
                c["name"] = new_name
                for net_ep in c["networks"].values():
                    aliases = list(net_ep.get("Aliases") or [])
                    if old_name in aliases:
                        aliases = [new_name if a == old_name else a for a in aliases]
                    elif new_name not in aliases:
                        aliases.append(new_name)
                    net_ep["Aliases"] = aliases
            if c.get("ip"):
                try:
                    eng.rpc.call({"op": "dns_set", "name": new_name, "ip": c["ip"]})
                except Exception:
                    pass
            eng.events.emit(
                "container", "rename", c["id"],
                {**c["labels"], "name": new_name, "oldName": old_name},
            )
            self.send_empty(204)
            return

        m = re.match(r"^/containers/([^/]+)/wait$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            # The Docker client blocks its start request until /wait is
            # acknowledged with response headers, then reads the status from the
            # body. Acknowledging first is what lets the container start at all;
            # the daemon is asked for the status afterwards.
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.flush()

            # The start request may still be in flight here, and a container
            # that has not started yet reads as exited with status 0 in the
            # daemon. Wait for start_container() to see the run begin, then ask
            # for the real status. The response headers are already out, so
            # blocking here does not hold up the client's start request.
            c["run_ev"].wait(timeout=10.0)
            w = eng.rpc.call({"op": "container_wait", "id": c["id"]})
            c["status"] = "exited"
            c["exit_code"] = w.get("exit_code", 0)
            # Deliver the status only after the attach streams are done: the
            # client stops following output as soon as it has the status, and a
            # fast container writes its last bytes at the same moment as it
            # exits.
            deadline = time.time() + 5.0
            while c.get("attach_count") and time.time() < deadline:
                time.sleep(0.005)
            body = json.dumps({"StatusCode": c["exit_code"], "Error": None})
            self.wfile.write(body.encode("utf-8"))
            self.wfile.flush()
            return

        m = re.match(r"^/containers/([^/]+)/attach$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            self._handle_attach(c, qs)
            return

        m = re.match(r"^/containers/([^/]+)/exec$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            body = self._read_json()
            try:
                rec = eng.create_exec(c, body)
                self.send_json(201, {"Id": rec["id"]})
            except Exception as exc:
                self.send_json(409, {"message": str(exc)})
            return

        m = re.match(r"^/exec/([^/]+)/start$", path)
        if m:
            eid = urllib.parse.unquote(m.group(1))
            with eng.lock:
                e = eng.execs.get(eid)
            if not e:
                self.send_json(404, {"message": f"No such exec instance: {eid}"})
                return
            # The body is EITHER the start options (JSON) OR, for an exec
            # created with AttachStdin, the stdin payload itself. A non-JSON
            # body must be kept, not dropped: reading it as JSON would swallow
            # the caller's bytes and leave the process with an empty stdin.
            raw = self._read_body()
            body = {}
            if raw:
                try:
                    body = json.loads(raw.decode("utf-8"))
                    raw = b""
                except (ValueError, UnicodeDecodeError):
                    body = {}
            self._handle_exec_start(e, body, raw)
            return

        m = re.match(r"^/(containers|exec)/([^/]+)/resize$", path)
        if m:
            self.send_empty(200)
            return

        self.send_json(404, {"message": f"unsupported POST {path}"})

    def _handle_build(self, qs):
        """POST /build: the classic builder, one Dockerfile instruction at a time.

        BuildKit would need its own daemon and a gRPC session; the docker CLI
        falls back to this protocol with DOCKER_BUILDKIT=0, and it is what the
        image store already supports.
        """
        eng = self.server.engine
        tags = qs.get("t") or []
        dockerfile = (qs.get("dockerfile") or ["Dockerfile"])[0] or "Dockerfile"
        buildargs = {}
        for raw in qs.get("buildargs") or []:
            try:
                buildargs.update(json.loads(raw))
            except ValueError:
                pass
        body = self._read_body()
        ctx_dir = os.path.join(eng.state_dir,
                               "build-ctx-" + secrets.token_hex(8))
        os.makedirs(ctx_dir, exist_ok=True)
        try:
            payload = body
            if payload[:2] == b"\x1f\x8b":
                import gzip
                payload = gzip.decompress(payload)
            import io
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tf:
                try:
                    tf.extractall(ctx_dir, filter="tar")
                except TypeError:
                    tf.extractall(ctx_dir)
            dockerfile_path = os.path.join(ctx_dir, dockerfile)
            if not os.path.isfile(dockerfile_path):
                raise BuildError("Cannot locate specified Dockerfile: %s"
                                 % dockerfile)
            with open(dockerfile_path, "r", errors="replace") as fh:
                text = fh.read()
            self._begin_chunked(200, "application/json")
            try:
                def emit(obj):
                    self._write_chunk(json.dumps(obj) + "\n")

                builder = ImageBuilder(eng, progress=emit,
                                       buildargs=buildargs)
                img_id = builder.build(ctx_dir, text, tags[0] if tags else None)
                for extra in tags[1:]:
                    if eng.images.tag(img_id, extra):
                        emit({"stream": "Successfully tagged %s\n" % extra})
                emit({"stream": "Successfully built %s\n"
                      % img_id.removeprefix("sha256:")[:12]})
            except Exception as exc:
                self._write_chunk(json.dumps({
                    "errorDetail": {"message": str(exc)},
                    "error": str(exc)}) + "\n")
            self._end_chunked()
        except Exception as exc:
            self.send_json(500, {"message": str(exc)})
        finally:
            shutil.rmtree(ctx_dir, ignore_errors=True)

    def do_PUT(self):
        eng = self.server.engine
        path, qs = self._parse_url()

        # PUT /containers/{id}/archive?path=DIR — `docker cp` into a container,
        # the only way to hand a running container a file. Buildx uses it to
        # install its buildkitd config, so a build cannot start without it.
        m = re.match(r"^/containers/([^/]+)/archive$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            dest = (qs.get("path") or ["/"])[0] or "/"
            body = self._read_body()
            if not body:
                self.send_json(400, {"message": "empty archive"})
                return
            try:
                eng.copy_into(c, dest, body)
            except Exception as exc:
                self.send_json(500, {"message": str(exc)})
                return
            self.send_empty(200)
            return

        self.send_json(404, {"message": "not found"})

    def do_DELETE(self):
        eng = self.server.engine
        path, qs = self._parse_url()

        m = re.match(r"^/containers/([^/]+)$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            force = (qs.get("force") or ["0"])[0] in ("1", "true", "True")
            try:
                eng.rpc.call({"op": "container_rm", "id": c["id"], "force": force})
            except Exception as e:
                self.send_json(409, {"message": str(e)})
                return
            with eng.lock:
                eng.containers.pop(c["id"], None)
            if c.get("health_stop") is not None:
                c["health_stop"].set()
            eng.events.emit("container", "destroy", c["id"], {**c["labels"], "name": c["name"]})
            self.send_empty(204)
            return

        m = re.match(r"^/networks/([^/]+)$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            if not n:
                self.send_json(404, {"message": "network not found"})
                return
            with eng.lock:
                eng.networks.pop(n["Id"], None)
            eng.events.emit("network", "destroy", n["Id"], {"name": n["Name"]})
            self.send_empty(204)
            return

        m = re.match(r"^/volumes/(.+)$", path)
        if m:
            vname = urllib.parse.unquote(m.group(1))
            # A declared or derived export is not the engine's to destroy: its
            # data lives on the server and the config still names it. Refusing is
            # the honest answer; 404 would read as "already gone".
            if eng.resolve_volume(vname) and is_nfs_source(vname):
                self.send_json(409, {"message":
                                     f"volume {vname} is a declared export and "
                                     f"cannot be removed"})
                return
            try:
                removed = eng.remove_volume(vname)
            except ValueError as e:
                self.send_json(400, {"message": str(e)})
                return
            if not removed:
                self.send_json(404, {"message": f"no such volume: {vname}"})
                return
            self.send_empty(204)
            return

        m = re.match(r"^/images/(.+)$", path)
        if m:
            self.send_json(200, [{"Untagged": urllib.parse.unquote(m.group(1))}])
            return

        self.send_json(404, {"message": f"unsupported DELETE {path}"})

    @staticmethod
    def _drain_frames(log_path, pos, tty, show_out, show_err, write_fn):
        with open(log_path, "rb") as f:
            f.seek(pos)
            while True:
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                stype = hdr[0]
                slen = struct.unpack(">I", hdr[4:8])[0]
                payload = f.read(slen)
                if len(payload) < slen:
                    break
                pos += 8 + slen
                if (stype == 1 and show_out) or (stype == 2 and show_err):
                    write_fn(payload if tty else (hdr + payload))
        return pos

    def _stream_log_file(self, log_path, tty, follow, show_out, show_err, write_fn, is_exited_fn, tail=None):
        pos = 0
        if tail is not None and tail != "all":
            try:
                tn = int(tail)
            except ValueError:
                tn = None
            if tn is not None and tn >= 0:
                if tn == 0:
                    if os.path.exists(log_path):
                        pos = os.path.getsize(log_path)
                    if not follow:
                        return
                elif os.path.exists(log_path):
                    frames = []
                    with open(log_path, "rb") as f:
                        while True:
                            hdr = f.read(8)
                            if len(hdr) < 8:
                                break
                            stype = hdr[0]
                            slen = struct.unpack(">I", hdr[4:8])[0]
                            payload = f.read(slen)
                            if len(payload) < slen:
                                break
                            pos += 8 + slen
                            if (stype == 1 and show_out) or (stype == 2 and show_err):
                                frames.append((hdr, payload))
                    lines = []
                    for hdr, pl in frames:
                        for ln in pl.splitlines(keepends=True):
                            lines.append((hdr[0], ln))
                    for stype, ln in lines[-tn:]:
                        if tty:
                            write_fn(ln)
                        else:
                            h = struct.pack(">BxxxI", stype, len(ln))
                            write_fn(h + ln)
                    if not follow:
                        return

        while True:
            if not os.path.exists(log_path):
                if is_exited_fn() or not follow:
                    break
                time.sleep(0.05)
                continue
            pos = self._drain_frames(log_path, pos, tty, show_out, show_err, write_fn)
            if not follow:
                break
            if is_exited_fn():
                # The daemon's log pump may still be flushing output written
                # just before the process exited, so drain a few more times
                # before closing the stream.
                for _ in range(3):
                    pos = self._drain_frames(log_path, pos, tty, show_out, show_err, write_fn)
                    time.sleep(0.02)
                break
            time.sleep(0.05)

    def _pump_stdin(self, fifo, raw_stdin, exec_rec):
        """Feed the exec's stdin: the bytes already read, then the live socket.

        Runs in its own thread because the request handler is busy streaming the
        output. Opening the FIFO for writing blocks until the guest opens it for
        reading — that is the synchronisation with process start, no sleep.
        """
        try:
            with open(fifo, "wb", buffering=0) as w:
                if raw_stdin:
                    w.write(raw_stdin)
                while True:
                    chunk = self._read_stdin_chunk(exec_rec)
                    if chunk is None:
                        continue
                    if not chunk:
                        break
                    try:
                        w.write(chunk)
                    except (BrokenPipeError, OSError):
                        break
        except (OSError, ValueError):
            return

    def _read_stdin_chunk(self, exec_rec, size=65536):
        """One read from the hijacked connection: bytes, b"" at EOF, None on idle.

        An idle stdin is normal (`exec -i` with a slow producer), so a timeout is
        None — "keep the FIFO open and try again" — while b"" ends the pump and
        closes the channel so the guest sees EOF.
        """
        sock = self.connection
        try:
            sock.settimeout(0.2)
            return sock.recv(size)
        except (socket.timeout, TimeoutError):
            return b"" if exec_rec.get("exited") else None
        except OSError:
            return b""

    def _stream_upgrade_or_chunked(self, log_path, tty, show_out, show_err, is_exited_fn,
                                   stdin_fifo="", raw_stdin=b"", exec_rec=None):
        upgrade = self.headers.get("Upgrade", "").lower() == "tcp"
        ctype = "application/vnd.docker.raw-stream" if tty else "application/vnd.docker.multiplexed-stream"

        if upgrade:
            self.send_response(101, "Switching Protocols")
            self._send_docker_headers()
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "tcp")
            self.send_header("Content-Type", ctype)
            self.end_headers()

            if stdin_fifo:
                threading.Thread(
                    target=self._pump_stdin,
                    args=(stdin_fifo, raw_stdin, exec_rec or {}),
                    daemon=True,
                ).start()

            def write_raw(b):
                self.wfile.write(b)
                self.wfile.flush()

            try:
                self._stream_log_file(log_path, tty, True, show_out, show_err, write_raw, is_exited_fn)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
        else:
            self._begin_chunked(200, ctype)
            try:
                self._stream_log_file(log_path, tty, True, show_out, show_err, self._write_chunk, is_exited_fn)
            except (BrokenPipeError, ConnectionResetError):
                return
            self._end_chunked()

    def _handle_logs(self, c, qs):
        follow = (qs.get("follow") or ["0"])[0] in ("1", "true", "True")
        show_out = (qs.get("stdout") or ["1"])[0] in ("1", "true", "True")
        show_err = (qs.get("stderr") or ["1"])[0] in ("1", "true", "True")
        tail = (qs.get("tail") or [None])[0]
        ctype = "application/vnd.docker.raw-stream" if c["tty"] else "application/vnd.docker.multiplexed-stream"
        self._begin_chunked(200, ctype)

        def is_exited():
            self.server.engine.refresh_container(c)
            return c["status"] == "exited"

        try:
            self._stream_log_file(c["log_path"], c["tty"], follow, show_out, show_err, self._write_chunk, is_exited, tail=tail)
        except (BrokenPipeError, ConnectionResetError):
            return
        self._end_chunked()

    def _handle_attach(self, c, qs):
        show_out = (qs.get("stdout") or ["1"])[0] in ("1", "true", "True")
        show_err = (qs.get("stderr") or ["1"])[0] in ("1", "true", "True")

        def is_exited():
            self.server.engine.refresh_container(c)
            return c["status"] == "exited"

        c["attach_count"] = c.get("attach_count", 0) + 1
        try:
            self._stream_upgrade_or_chunked(c["log_path"], c["tty"], show_out, show_err, is_exited)
        finally:
            c["attach_count"] = c.get("attach_count", 1) - 1

    def _handle_exec_start(self, e, body, raw_stdin=b""):
        eng = self.server.engine
        detach = bool(body.get("Detach", False))
        tty = bool(body.get("Tty", e["tty"]))
        e["tty"] = tty
        # `docker exec -i` puts the caller's bytes on the connection AFTER the
        # 101 handshake, so the process must start with a live channel, not a
        # finished file. A FIFO gives kboxd's guest a blocking read, and this
        # side pumps the socket into it while it streams the output back.
        e["stdin_fifo"] = ""
        if e.get("attach_stdin") and not detach:
            # A per-exec FIFO under the STATE dir, not /tmp/kboxd-logs: that
            # directory is root-owned (created when the daemon ran as root) and
            # mkfifo there fails with EACCES while the shim runs as the role
            # user. state_dir belongs to whoever runs the shim.
            fifo_dir = os.path.join(eng.state_dir, "stdin")
            try:
                os.makedirs(fifo_dir, exist_ok=True)
            except OSError:
                pass
            fifo = os.path.join(fifo_dir, f"exec-{e['id']}.fifo")
            try:
                os.unlink(fifo)
            except OSError:
                pass
            try:
                os.mkfifo(fifo, 0o600)
                e["stdin_fifo"] = fifo
                e["stdin_path"] = fifo
            except OSError as exc:
                sys.stderr.write(f"[dockerd] stdin fifo: {exc}\n")
                sys.stderr.flush()
        try:
            eng.start_exec(e)
        except Exception as exc:
            sys.stderr.write(f"[dockerd] exec_start error: {exc}\n")
            sys.stderr.flush()
            self.send_json(500, {"message": str(exc)})
            return

        if detach:
            self.send_empty(200)
            return

        self._stream_upgrade_or_chunked(
            e["log_path"],
            tty,
            e["attach_stdout"],
            e["attach_stderr"],
            lambda: e["exited"],
            stdin_fifo=e.get("stdin_fifo") or "",
            raw_stdin=raw_stdin,
            exec_rec=e,
        )
        e["done_ev"].wait(timeout=2.0)
        try:
            if os.path.exists(e["log_path"]):
                os.unlink(e["log_path"])
        except OSError:
            pass
        # The FIFO is per-exec and dead once the pump finished; an unlinked
        # fifo keeps no bytes, so this only stops the directory filling up.
        if e.get("stdin_fifo"):
            try:
                os.unlink(e["stdin_fifo"])
            except OSError:
                pass

    def _handle_events(self, qs):
        filters = (qs.get("filters") or [None])[0]
        fobj = json.loads(filters) if filters else {}
        self._begin_chunked(200, "application/json")
        q = self.server.engine.events.subscribe()
        try:
            while True:
                try:
                    ev = q.get(timeout=0.5)
                except queue.Empty:
                    continue
                if fobj:
                    if "type" in fobj and ev["Type"] not in fobj["type"]:
                        continue
                    if "event" in fobj and ev["Action"] not in fobj["event"]:
                        continue
                    if "label" in fobj:
                        attrs = ev.get("Actor", {}).get("Attributes", {})
                        ok = True
                        for expr in fobj["label"]:
                            if "=" in expr:
                                k, v = expr.split("=", 1)
                                if attrs.get(k) != v:
                                    ok = False
                            elif expr not in attrs:
                                ok = False
                        if not ok:
                            continue
                self._write_chunk(json.dumps(ev) + "\n")
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.server.engine.events.unsubscribe(q)


def _serve_unix(path, engine, verbose):
    """Serve the same Docker Engine API on a unix socket.

    The Docker CLI and Compose default to DOCKER_HOST unset + /var/run/docker.sock,
    so a socket is what makes them work with no configuration at all. A stale
    socket from a previous run is removed first: bind() fails with EADDRINUSE on
    a leftover inode even though nothing is listening on it.
    """
    if path.startswith("unix://"):
        # Accept the DOCKER_HOST spelling too: a URL here used to become a
        # directory literally named "unix:" under the cwd.
        path = path[len("unix://"):]
    if os.path.exists(path):
        os.unlink(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    class UnixHTTPServer(ThreadingHTTPServer):
        address_family = socket.AF_UNIX
        daemon_threads = True

        def server_bind(self):
            # HTTPServer.server_bind() resolves the address as (host, port) and
            # calls getfqdn() on it, which a socket path cannot be.
            socketserver.TCPServer.server_bind(self)
            self.server_name = path
            self.server_port = 0

    srv = UnixHTTPServer(path, DockerHandler)
    srv.engine = engine
    srv.verbose = verbose
    os.chmod(path, 0o666)
    sys.stderr.write(f"kbox-dockerd listening on unix://{path} -> {engine.rpc.sock_path}\n")
    sys.stderr.flush()
    return srv


def main():
    ap = argparse.ArgumentParser(description="Docker Engine HTTP server backed by kbox daemon")
    ap.add_argument("--kbox-sock", default="/tmp/kboxd.sock", help="kbox daemon RPC socket")
    ap.add_argument("--listen", default="0.0.0.0:2375", help="TCP listen host:port")
    ap.add_argument("--state-dir", default="/tmp/kbox-dockerd", help="Image/state cache directory")
    ap.add_argument("--config", default=None, help="Path to kbox-config.yaml")
    ap.add_argument("--unix-socket", action="append", default=[], help="Also serve on this unix socket path")
    ap.add_argument("--registry-mirror", action="append", default=[],
                    help="Pull-through mirror host[:port] tried before the upstream registry")
    ap.add_argument("--import-dir", action="append", default=[], help="Pre-import host dir as REF=DIR")
    ap.add_argument("--docker-config", default="",
                    help="Path to a docker config.json whose `auths` are used for registry pulls")
    ap.add_argument("--path-map", action="append", default=[], help="Rewrite bind path HOST_PREFIX:LOCAL_PREFIX")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.state_dir, exist_ok=True)
    rpc = KboxRpcClient(args.kbox_sock)
    for _ in range(50):
        try:
            if rpc.call({"op": "ping"}).get("ok"):
                break
        except Exception:
            time.sleep(0.1)

    path_maps = []
    for pm in args.path_map:
        if ":" in pm:
            s, d = pm.split(":", 1)
            path_maps.append((s, d))

    engine = DockerEngineState(rpc, args.state_dir, path_maps=path_maps, config_path=args.config)
    engine.images.registry_mirrors = list(args.registry_mirror or [])
    engine.images.registry_auth = load_registry_auth(args.docker_config or None)
    if engine.images.registry_auth:
        print("[dockerd] registry credentials loaded for: "
              + ", ".join(sorted(engine.images.registry_auth)), flush=True)

    for imp in args.import_dir:
        if "=" in imp:
            ref, src = imp.split("=", 1)
            engine.images.import_dir_as_image(ref, src)

    host, port_str = args.listen.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port_str)), DockerHandler)
    srv.engine = engine
    srv.verbose = args.verbose
    sys.stderr.write(f"kbox-dockerd listening on http://{host}:{port_str} -> {args.kbox_sock}\n")
    sys.stderr.flush()
    # SIGUSR1 dumps every thread's Python stack into the log; the only way to
    # see where a wedged request is stuck without a debugger in the image.
    faulthandler.register(signal.SIGUSR1, file=sys.stderr, all_threads=True)
    servers = [srv]
    for spec in args.unix_socket or []:
        servers.append(_serve_unix(spec, engine, args.verbose))
    for extra in servers[1:]:
        threading.Thread(target=extra.serve_forever, daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for extra in servers:
            extra.server_close()


if __name__ == "__main__":
    main()
