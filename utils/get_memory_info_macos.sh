#!/bin/sh

#ret=-1
result=$( top -l 1 | grep -e PhysMem: -e csmgrd )

#ARR=(${result//\n\/})
IFS=$'\n' list=(${result})

for line in ${list[@]}
do
  IFS=$' ' aline=($line)
#  ARR==(${line// / })
  if [ ${aline[0]} = "PhysMem:" ]; then
    for ARR in ${aline[@]}
    do
      if [ ${ARR} = "used" ]; then
        if [[ ${num} = *M ]]; then
          let kb=${num%M}*1024
        elif [[ ${num} = *G ]]; then
          let kb=${num%G}*1024*1024
        elif [[ ${num} = *K ]]; then
          kb=${num%K}
        fi
        used_kb=${kb}
      elif [ ${ARR} = "unused." ]; then
        if [[ ${num} = *M ]]; then
          let kb=${num%M}*1024
        elif [[ ${num} = *G ]]; then
          let kb=${num%G}*1024*1024
        elif [[ ${num} = *K ]]; then
          kb=${num%K}
        fi
        unused_kb=${kb}
      fi
      num=$ARR
    done

  elif [ ${aline[1]} = "csmgrd" ]; then
    num=${aline[7]}

    if [[ ${num} = *M ]]; then
      let kb=${num%M}*1024
    elif [[ ${num} = *G ]]; then
      let kb=${num%G}*1024*1024
    elif [[ ${num} = *K ]]; then
      kb=${num%K}
    fi
	csmgrd_kb=${kb}
  else
    echo -1
    exit 0
  fi

done

# MemTotal
MemTotal=$((used_kb+unused_kb))

# MemFree
MemFree=${unused_kb}

# MemAvailable
if [[ ${unused_kb} < ${csmgrd_kb} ]]; then
  MemAvailable=${unused_kb}
else
  MemAvailable=$((unused_kb-csmgrd_kb))
fi

echo ${MemTotal}","${MemFree}","${MemAvailable}
