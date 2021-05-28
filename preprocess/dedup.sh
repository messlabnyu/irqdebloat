#!/bin/bash

ddir=$1

WS=/home/hu/workspace
DEDUP=/home/hu/workspace/dedup
TMP=/home/hu/tmp
cnt=0
for f in `find $ddir -name "*.tar.gz"`;
do
	tar -xzf $f -C $TMP;
	for d in `find $TMP -name "qemu_*"`;
	do
		#find $d -name "*.pact"|xargs sha1sum|cut -d ' ' -f 1|uniq>>$WS/$cnt.log&
		find $d -name "*.pact"|xargs sha1sum|awk '!_[$1]++'>>$WS/$cnt.log&
		cnt=$(($cnt+1))
	done
	wait
	cat $WS/*.log|awk '!_[$1]++'|xargs -n 2 bash -c 'cp $2 $0/trace_$1.pact' $DEDUP
	rm $WS/*.log
	rm -rf $TMP/*
	cnt=0
done
