#!/bin/sh
# Does a parent wake for a child that exec'd and exited?
#
# Item 28's evidence was two children that had exec'd (their comm was
# "memfd:kbox-shad", the injected binary), both zombies, while the parent sat in
# rt_sigsuspend with SigPnd=0: the SIGCHLD that should have woken it was lost
# with a SIG_SETMASK. A child that runs a shell builtin never execs, so this
# checks the shape that actually failed: every child execs a binary and exits
# with a status the parent must collect.
#
# Each round prints its number first, so a hang names the round it happened in.
# The whole run is bounded by the caller (timeout) for the same reason.
#
# Results: /vol/results/wait-exec.log
exec > /vol/results/wait-exec.log 2>&1

rounds=${ROUNDS:-300}
i=0
bad=0
while [ "$i" -lt "$rounds" ]; do
    echo "round $i pid=$$"
    sh -c 'exit 3' &
    p1=$!
    sh -c 'exit 4' &
    p2=$!
    wait $p1
    s1=$?
    wait $p2
    s2=$?
    if [ "$s1" -ne 3 ] || [ "$s2" -ne 4 ]; then
        bad=$((bad + 1))
        echo "round $i: statuses $s1 $s2 (want 3 4)"
    fi
    i=$((i + 1))
done

echo "exec children: rounds=$i bad=$bad"

# The same shape with a child that runs long enough to overlap the parent's
# next fork, so the exits arrive while another child is being set up.
i=0
bad=0
while [ "$i" -lt "$rounds" ]; do
    sleep 0.01 &
    p1=$!
    sh -c 'exit 5' &
    p2=$!
    wait $p2
    s2=$?
    wait $p1
    s1=$?
    if [ "$s1" -ne 0 ] || [ "$s2" -ne 5 ]; then
        bad=$((bad + 1))
        echo "overlap round $i: statuses $s1 $s2 (want 0 5)"
    fi
    i=$((i + 1))
done
echo "overlapping children: rounds=$i bad=$bad"

if [ "$bad" -eq 0 ]; then
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL"
fi
echo done
