#!/bin/bash

ret=-1
while read line
do
  ARR=(${line})

  if [ ${ARR[0]} = "MemTotal:" ]; then
    ret=${ARR[1]},
  elif [ ${ARR[0]} = "MemFree:" ]; then
    ret=$ret${ARR[1]},
  elif [ ${ARR[0]} = "MemAvailable:" ]; then
    ret=$ret${ARR[1]}
    echo ${ret}
    exit 0
  else
    echo "-1"
    exit 0
  fi
done < <( cat /proc/meminfo | grep Mem )
