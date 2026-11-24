/* SPDX-License-Identifier: MIT */

/* kbox entry point: parse CLI arguments and boot the rootfs image. */

#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#include "daemon.h"
#include "kbox/cli.h"
#include "kbox/image.h"

/* A crash in the daemon takes every container with it, and the only evidence
 * left behind is "Exit Code: 139" plus whatever the container happened to
 * print last. Print where it died instead of guessing from a log tail.
 *
 * The faulting instruction is taken from the signal context: backtrace() walks
 * the stack of the handler itself, so on a machine built without frame
 * pointers it reports crash_handler and nothing else, which names the wrong
 * frame and hides the defect.
 */
static void crash_handler(int sig, siginfo_t *si, void *ctx)
{
    void *frames[64];
    int n = backtrace(frames, 64);
    unsigned long pc = 0;
    unsigned long lr = 0;
    char line[192];
    int len;

    if (ctx) {
        ucontext_t *uc = (ucontext_t *) ctx;

#if defined(__aarch64__)
        pc = (unsigned long) uc->uc_mcontext.pc;
        lr = (unsigned long) uc->uc_mcontext.regs[30];
#elif defined(__x86_64__)
        pc = (unsigned long) uc->uc_mcontext.gregs[REG_RIP];
        lr = (unsigned long) uc->uc_mcontext.gregs[REG_RBP];
#else
        (void) uc;
#endif
    }

    const char *name = sig == SIGSEGV   ? "SIGSEGV"
                       : sig == SIGBUS  ? "SIGBUS"
                       : sig == SIGABRT ? "SIGABRT"
                                        : "signal";
    len = snprintf(line, sizeof(line), "kbox: fatal: %s addr=%p pc=%p lr=%p\n",
                   name, si ? si->si_addr : NULL, (void *) pc, (void *) lr);
    if (len > 0)
        (void) write(STDERR_FILENO, line, (size_t) len);
    (void) write(STDERR_FILENO, "kbox: backtrace:\n", 17);
    backtrace_symbols_fd(frames, n, STDERR_FILENO);
    _exit(139);
}

int main(int argc, char *argv[])
{
    struct sigaction sa;
    struct kbox_image_args args;

    /* A write to a socket whose peer has gone must fail with EPIPE, not kill
     * the supervisor. The bridge writes into the tracee's socketpair ends and
     * sendfile writes into them too; the peer closes in ordinary tests (and in
     * ordinary programs), and the default disposition turned that into exit
     * status 141 with every container in the daemon frozen.
     */
    signal(SIGPIPE, SIG_IGN);

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_NODEFER | SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    if (argc >= 2 && strcmp(argv[1], "daemon") == 0)
        return kbox_daemon_main(argc - 1, argv + 1);

    if (kbox_parse_args(argc, argv, &args) < 0)
        return 1;

    return kbox_run_image(&args) < 0 ? 1 : 0;
}
