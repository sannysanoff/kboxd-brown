/* Force plain fork() wherever a caller asks for vfork().
 *
 * kbox performs an exec by rewriting the pathname in the tracee's memory. When
 * the caller used CLONE_VM|CLONE_VFORK -- which posix_spawn, popen and system
 * all do -- that memory is shared with the parent, so the rewrite lands in the
 * parent too. kbox snapshots the bytes it overwrites and restores them on the
 * parent's next syscall, but the restore is not exhaustive: CPython dies with
 * SIGSEGV on its first captured subprocess.run(), and because the damage is to
 * memory the crash site moves between runs.
 *
 * clone3 carries its flags in a struct, so kbox rewrites them there and the
 * vfork never reaches the kernel. clone and vfork() pass flags in a register,
 * which the dispatcher forwards untouched, so those callers keep the shared
 * address space and the incomplete restore path.
 *
 * Answering ENOSYS to the clone flags is not an option: dash calls clone
 * directly and has no fallback, so the guest loses the ability to start any
 * child ("Cannot fork"). Overriding vfork here keeps every caller on the
 * success path while removing the shared address space that causes the damage.
 *
 * Linux documents vfork as "the same as fork except the parent is suspended",
 * and callers must behave identically with either, so fork is a legal and
 * observably equivalent implementation.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>

pid_t vfork(void)
{
    return fork();
}
