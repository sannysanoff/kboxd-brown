#!/bin/sh
# The command-substitution loop while other processes fork, exec and are reaped.
#
# The losses were measured "once a build is compiling and reaping children", so
# the load here is child churn rather than a compiler: four background loops
# each fork an exec'd child and wait for it, and the substitution loop runs on
# top of that.
#
# Results: /vol/results/pipe-churn.log
exec > /vol/results/pipe-churn.log 2>&1

rounds=${ROUNDS:-1500}
churn=${CHURN:-1200}
V=5.3.0-0-g0

i=0
while [ "$i" -lt 4 ]; do
    (
        j=0
        while [ "$j" -lt "$churn" ]; do
            sh -c 'exit 0' &
            wait $!
            j=$((j + 1))
        done
    ) &
    i=$((i + 1))
done

i=0
bad=0
while [ "$i" -lt "$rounds" ]; do
    got=`echo "$V" | tr ".g-" " " | awk '{print $2}'`
    if [ "$got" != "3" ]; then
        bad=$((bad + 1))
        [ "$bad" -le 3 ] && echo "round $i: awk=[$got]"
    fi
    i=$((i + 1))
done
wait

echo "substitutions under child churn: rounds=$i bad=$bad"
echo "interrupted lines: $(grep -ac 'Interrupted system call' /vol/results/pipe-churn.log)"
if [ "$bad" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
echo done
