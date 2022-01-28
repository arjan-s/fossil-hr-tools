#!/bin/bash

rm -f dumpstate.zip btsnoop_hci.log
adb bugreport
unzip dumpstate*.zip FS/data/log/bt/btsnoop_hci.log
mv FS/data/log/bt/btsnoop_hci.log .
rm -rf FS dumpstate*.zip
[ -f btsnoop_hci.log ] && tshark -r btsnoop_hci.log -T json >btsnoop_hci.json
