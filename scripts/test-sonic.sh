#!/bin/bash

DEBUG=0
BUILD=${1:-x86_64-native-linuxapp-gcc}
COREMASK=${2:-E} # default using cores 0 and 1
CONNECTALDIR=/home/hwang/dev/connectal
PROJ=examples/memread128

if [ $DEBUG -eq 1 ]; then
GDB=gdb
else
GDB="LD_PRELOAD=libSegFault.so SEGFAULT_USE_ALTSTACK=1 SEGFAULT_OUTPUT_NAME=bin/bsimexe-segv-output.txt"
fi

echo running bsim
$CONNECTALDIR/$PROJ/bluesim/bin/bsim -w & bsimpid=$!
echo bsimpid $bsimpid

RUN_ARGS="-c $COREMASK -n 4 \
	      --vdev eth_sonic1 --vdev eth_sonic2 -- \
	      --total-num-mbufs=2048 -ia --no-flush-rx \
          --tx-limits=1000 --link-lib=$CONNECTALDIR/$PROJ/bluesim/jni/connectal.so"

(sleep 1 && echo stop) |
sudo $GDB $BUILD/app/testpmd $RUN_ARGS;

retcode=$?;
kill $bsimpid;
exit $retcode;
