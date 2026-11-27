#!/usr/bin/env python3
"""The vfork shim must be loadable, built, and actually replace vfork.

Why this needs a test of its own: kbox rewrites an exec pathname in the tracee's
memory, which a CLONE_VM|CLONE_VFORK parent shares. clone3 carries its flags in
a struct kbox can rewrite; clone() and vfork() pass them in a register that a
seccomp user-notification reply cannot change (the response struct carries only
a return value and an errno). So the only lever inside the guest is LD_PRELOAD,
and a preload that silently stops building, stops exporting the symbol, or stops
being collected into the vendor context turns back into the invisible dependency
it used to be -- the guest crashes with SIGSEGV somewhere unrelated, and nothing
points at the shim.

What this holds:
  * the engine's own build produces the .so, in the tree root, next to kbox;
  * the artefact exports `vfork`, so LD_PRELOAD resolves it over libc;
  * a program that calls vfork() still works with the shim preloaded (a shim
    that broke the call would take every posix_spawn and popen with it);
  * the shim replaces the symbol libc would otherwise answer.
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SO = os.path.join(ROOT, "kbox-novfork.so")


def fail(msg):
    print("FAIL  " + msg, file=sys.stderr)
    sys.exit(1)


def pass_(msg):
    print("PASS  " + msg)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# --- the engine's build produces the shim ----------------------------------
if not os.path.exists(SO):
    # check-unit builds the test binary but does not run `make all`; build it
    # the same way the release build does rather than failing on a clean tree.
    built = run(["make", "-s", "kbox-novfork.so"], cwd=ROOT)
    if built.returncode != 0:
        fail("the engine's build does not produce kbox-novfork.so:\n"
             + built.stdout + built.stderr)
pass_("the engine's build produces kbox-novfork.so")

# --- it exports the symbol LD_PRELOAD needs --------------------------------
nm = run(["nm", "-D", "--defined-only", SO])
if nm.returncode != 0:
    fail("cannot read the shim's dynamic symbols: " + nm.stderr)
if not any(line.split()[-1] == "vfork" for line in nm.stdout.splitlines()):
    fail("kbox-novfork.so does not define `vfork`; LD_PRELOAD would be a no-op")
pass_("the shim defines vfork")

# --- a vfork() caller still works with the shim ---------------------------
work = tempfile.mkdtemp(prefix="novfork-")
src = os.path.join(work, "vf.c")
exe = os.path.join(work, "vf")
with open(src, "w") as fh:
    fh.write(
        "#define _GNU_SOURCE\n"
        "#include <stdio.h>\n"
        "#include <unistd.h>\n"
        "int main(void){ pid_t p = vfork(); if (p == 0) _exit(0);\n"
        "  if (p < 0) { perror(\"vfork\"); return 1; }\n"
        "  printf(\"ok\\n\"); return 0; }\n"
    )
cc = run(["cc", "-o", exe, src])
if cc.returncode != 0:
    fail("cannot build a vfork() probe: " + cc.stderr)

plain = run([exe])
if plain.returncode != 0 or "ok" not in plain.stdout:
    fail("the vfork() probe does not pass without the shim:\n"
         + plain.stdout + plain.stderr)

preloaded = run([exe], env=dict(os.environ, LD_PRELOAD=SO))
if preloaded.returncode != 0 or "ok" not in preloaded.stdout:
    fail("a vfork() caller fails with the shim preloaded, so the shim breaks\n"
         "the very calls it exists to serve:\n"
         + preloaded.stdout + preloaded.stderr)
pass_("a vfork() caller still works with the shim preloaded")

# --- and the shim is what answers, not libc -------------------------------
# LD_DEBUG=bindings prints every symbol resolution; the shim's path appearing
# next to `vfork` proves the preload won rather than being loaded and ignored.
dbg = run([exe], env=dict(os.environ, LD_PRELOAD=SO, LD_DEBUG="bindings"))
if "kbox-novfork.so" not in dbg.stderr or "vfork" not in dbg.stderr:
    fail("LD_DEBUG shows no binding of vfork from the shim, so the preload is\n"
         "loaded but not used")
bound = [
    line for line in dbg.stderr.splitlines()
    if "vfork" in line and "kbox-novfork.so" in line
]
if not bound:
    fail("the shim is loaded but does not provide vfork")
pass_("the shim answers vfork, not libc")

pass_("the vfork shim is built, loadable and effective")
