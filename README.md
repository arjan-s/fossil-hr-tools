# Fossil Hybrid HR tools

## Introduction
This repository contains some scripts I used for extracting and analyzing the Fossil Hybrid HR apps and watchfaces.

For packing/unpacking watch apps and encoding image files, I used the scripts from [Fossil Hybrid HR SDK](https://github.com/dakhnod/Fossil-HR-SDK) by Daniel Dakhno.

## Files
| File | Description |
| --- | --- |
|`scripts/retrieve_btsnoop.sh`|Retrieve BT HCI snoop file from phone over ADB and convert to JSON using tshark|
|`scripts/parse_btsnoop_json.py`|Parse `btsnoop_hci.json`, show packet information and save packets to individual files|
|`examples/*`|Example JSON files as extracted from watchface apps created by the official app (no binaries and images due to copyright concerns)|

## How to use this
- Enable developer mode on the phone
- Turn off Bluetooth
- Turn on Bluetooth HCI snoop log in the developer settings
- Turn on Bluetooth
- Perform actions with the official app, like send a watchface to the watch
- Run `retrieve_btsnoop.sh`
- Run `parse_btsnoop_json.py btsnoop_hci.json`
- Run `unpack.py` (from the SDK) on one of the watchapp files
- Manually analyze the unpacked files
- Make changes manually
- Run `pack.py` on the watchapp directory to create a new .wapp file that can be installed on the watch
