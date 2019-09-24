#!/bin/bash

cat /etc/shadow | grep -v "^root:" | while read line; do
  echo $line | awk -F':' '{print $2}' | grep -v "^\*$" | grep -q -v "^\!\!$"
  if [ $? == 0 ]; then
    echo $line | awk -F':' '{print $1}' | while read USERNAME; do
      PASSWD=$PASSWORD
      echo "$USERNAME:$1" | chpasswd
      echo "USERNAME=$USERNAME"
    done
  fi
done
