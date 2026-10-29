#!/bin/bash
# usage: ./capture.sh <label> "<command to run>"
# captures execve provenance for one labelled activity into captures/<label>.log
LABEL=$1; CMD=$2
OUT=$(dirname "$0")/../captures/${LABEL}.log
START=$(date +%H:%M:%S)
sleep 1
bash -c "$CMD"
sleep 1
sudo ausearch -k lotl_exec -ts "$START" --raw > "$OUT"
echo "saved $(grep -c '^type=SYSCALL' "$OUT") execs to $OUT"
