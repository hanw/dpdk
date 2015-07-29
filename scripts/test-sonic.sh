#!/bin/bash

DEBUG=0
BUILD=${1:-x86_64-native-linuxapp-gcc}
COREMASK=${2:-E} # default using cores 0 and 1
CONNECTALDIR=/home/hwang/dev/sonic-lite
PROJ=sonic
JNI_PATH=$CONNECTALDIR/$PROJ/bluesim/jni

if [ $DEBUG -eq 1 ]; then
GDB=gdb
else
GDB="LD_PRELOAD=libSegFault.so SEGFAULT_USE_ALTSTACK=1 SEGFAULT_OUTPUT_NAME=bin/bsimexe-segv-output.txt"
fi

#echo running bsim
#$CONNECTALDIR/$PROJ/bluesim/bin/bsim -w & bsimpid=$!
#echo bsimpid $bsimpid
#sleep 2

RUN_ARGS="-c $COREMASK -n 2 \
	      --vdev eth_sonic0 --vdev eth_sonic1 -- \
	      --total-num-mbufs=2048 -i --no-flush-rx \
          --tx-limits=1000"

#(sleep 1 && echo stop) |
sudo LD_LIBRARY_PATH=$JNI_PATH $GDB $BUILD/app/testpmd $RUN_ARGS;

retcode=$?;
#kill $bsimpid;
exit $retcode;
