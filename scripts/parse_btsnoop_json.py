#!/usr/bin/env python3

import json
import os.path
import sys

if len(sys.argv) != 2:
    raise ValueError('Please provide a file name to open')


def to_int(byte_array):
    return int("".join(reversed(byte_array)), 16)


def to_string(byte_array):
    try:
        parsed_string = bytes.fromhex("".join(byte_array)).decode("utf-8")
    except Exception:
        parsed_string = "ERROR: could not parse string: " + " ".join(byte_array)
    return parsed_string


def to_binary(byte_array):
    result = []
    for byte in byte_array:
        result.append(bin(int(byte, 16))[2:].zfill(8))
    return " ".join(result)


def pop_elements(packet, count):
    result = []
    for x in range(count):
        result.append(packet.pop(0))
    return result


def parse_header(packet):
    print("Header")
    print(" ".join(pop_elements(packet, 2)) + " : unknown")
    print(" ".join(pop_elements(packet, 3)) + " : handle+version")
    print(" ".join(pop_elements(packet, 4)) + " : unknown (usually zeroes)")
    file_length = pop_elements(packet, 4)
    print(" ".join(file_length) + " : file length = " + str(to_int(file_length)))


def parse_notification(packet):
    print("Payload")
    main_buffer_length = pop_elements(packet, 2)
    print(" ".join(main_buffer_length) + " : main buffer length = " + str(to_int(main_buffer_length)))
    length_buffer_length = pop_elements(packet, 1)
    print(" ".join(length_buffer_length) + " : length buffer length = " + str(to_int(length_buffer_length)))
    print(" ".join(pop_elements(packet, 1)) + " : notification type")
    flags = pop_elements(packet, 1)
    print(" ".join(flags) + " : flags = " + to_binary(flags))
    print(" ".join(pop_elements(packet, 1)) + " : msgid length")
    print(" ".join(pop_elements(packet, 1)) + " : pkgname crc length")
    title_length = pop_elements(packet, 1)
    print(" ".join(title_length) + " : title length = " + str(to_int(title_length)))
    sender_length = pop_elements(packet, 1)
    print(" ".join(sender_length) + " : sender length = " + str(to_int(sender_length)))
    message_length = pop_elements(packet, 1)
    print(" ".join(message_length) + " : message length = " + str(to_int(message_length)))
    print(" ".join(pop_elements(packet, 1)) + " : extra flags length")
    print(" ".join(pop_elements(packet, 1)) + " : timestamp length")
    print(" ".join(pop_elements(packet, 4)) + " : message id")
    print(" ".join(pop_elements(packet, 4)) + " : pkgname crc")
    title = pop_elements(packet, to_int(title_length))
    print(" ".join(title) + " : title = " + to_string(title))
    sender = pop_elements(packet, to_int(sender_length))
    print(" ".join(sender) + " : sender = " + to_string(sender))
    message = pop_elements(packet, to_int(message_length))
    print(" ".join(message) + " : message = " + to_string(message))
    print(" ".join(pop_elements(packet, 4)) + " : extra flags?")
    timestamp = pop_elements(packet, 4)
    print(" ".join(timestamp) + " : timestamp = " + str(to_int(timestamp)))


def parse_quick_replies(packet):
    print("Payload")
    if len(packet) < 17:
        print("Packet too short!")
        return
    print(" ".join(pop_elements(packet, 9)) + " : magic header? :)")
    payload_length = pop_elements(packet, 4)
    print(" ".join(payload_length) + " : payload length = " + str(to_int(payload_length)))
    while len(packet) > 4:
        part_length = pop_elements(packet, 2)
        print(" ".join(part_length) + " : part length = " + str(to_int(part_length)))
        print(" ".join(pop_elements(packet, 2)) + " : reply id")
        message_length = pop_elements(packet, 2)
        print(" ".join(message_length) + " : message length = " + str(to_int(message_length)))
        icon_name_length = pop_elements(packet, 2)
        print(" ".join(icon_name_length) + " : icon name length = " + str(to_int(icon_name_length)))
        message = pop_elements(packet, to_int(message_length))
        print(" ".join(message) + " : message = " + to_string(message))
        icon_name = pop_elements(packet, to_int(icon_name_length))
        print(" ".join(icon_name) + " : icon name = " + to_string(icon_name))


def parse_notification_filter(packet):
    print("Payload")
    while len(packet) > 4:
        part_length = pop_elements(packet, 2)
        print(" ".join(part_length) + " : part length = " + str(to_int(part_length)))
        print(" ".join(pop_elements(packet, 1)) + " : part ID (04 = pkgname crc)")
        print(" ".join(pop_elements(packet, 1)) + " : pkgname crc length")
        print(" ".join(pop_elements(packet, 4)) + " : pkgname crc")
        print(" ".join(pop_elements(packet, 1)) + " : part ID (80 = group)")
        print(" ".join(pop_elements(packet, 2)) + " : group")
        print(" ".join(pop_elements(packet, 1)) + " : part ID (c1 = priority)")
        print(" ".join(pop_elements(packet, 2)) + " : priority")
        if len(packet) == 4:
            break
        print(" ".join(pop_elements(packet, 1)) + " : part ID (82 = icon name)")
        icon_part_length = pop_elements(packet, 1)
        print(" ".join(icon_part_length) + " : icon part length = " + str(to_int(icon_part_length)))
        ordinal = pop_elements(packet, 2)
        print(" ".join(ordinal) + " : ordinal (multi icon app?) = " + to_binary(ordinal))
        icon_name_length = pop_elements(packet, 1)
        print(" ".join(icon_name_length) + " : icon name length = " + str(to_int(icon_name_length)))
        icon_name = pop_elements(packet, to_int(icon_name_length))
        print(" ".join(icon_name) + " : icon name = " + to_string(icon_name))
        if to_int(ordinal) < 255:
            for x in range(0, to_int(ordinal)):
                unknown = pop_elements(packet, 2)
                print(" ".join(unknown) + " : unknown = " + to_binary(unknown))
                icon_name_length = pop_elements(packet, 1)
                print(" ".join(icon_name_length) + " : icon name length = " + str(to_int(icon_name_length)))
                icon_name = pop_elements(packet, to_int(icon_name_length))
                print(" ".join(icon_name) + " : icon name = " + to_string(icon_name))


def parse_icons(packet):
    print("Payload")
    while len(packet) > 4:
        part_length = pop_elements(packet, 2)
        print(" ".join(part_length) + " : part length = " + str(to_int(part_length)))
        icon_name = []
        while not icon_name or icon_name[-1] != '00':
            icon_name.extend(pop_elements(packet, 1))
        print(" ".join(icon_name) + " : icon name = " + to_string(icon_name))
        icon_width = pop_elements(packet, 1)
        print(" ".join(icon_width) + " : icon width = " + str(to_int(icon_width)))
        icon_height = pop_elements(packet, 1)
        print(" ".join(icon_height) + " : icon height = " + str(to_int(icon_height)))
        print(" ".join(pop_elements(packet, to_int(part_length) - 2 - len(icon_name))) + " : icon data")


def parse_installed_apps(packet):
    print("Payload")
    while len(packet) > 4:
        part_length = pop_elements(packet, 2)
        print(" ".join(part_length) + " : part length = " + str(to_int(part_length)))
        print(" ".join(pop_elements(packet, 1)) + " : unknown")
        name_length = pop_elements(packet, 1)
        print(" ".join(name_length) + " : name length = " + str(to_int(name_length)))
        app_name = pop_elements(packet, to_int(name_length))
        print(" ".join(app_name) + " : app name = " + to_string(app_name))
        print(" ".join(pop_elements(packet, 1)) + " : handle")
        hash = pop_elements(packet, 4)
        print(" ".join(hash) + " : hash = " + str(to_int(hash)))
        print(" ".join(pop_elements(packet, 4)) + " : version")


def get_watchapp_name(packet_data):
    display_name_start = 1 + 12 + 4 + 8 + 4+4+4+4
    display_name_start_pos = to_int(packet_data[display_name_start:display_name_start+4])
    display_name_end = 1 + 12 + 4 + 8 + 4+4+4+4+4
    display_name_end_pos = to_int(packet_data[display_name_end:display_name_end+4])
    current_pos = display_name_start_pos + 1
    while current_pos < display_name_end_pos:
        file_name_length = to_int(packet_data[current_pos:current_pos+1])
        current_pos += 1
        file_name = to_string(packet_data[current_pos:current_pos+file_name_length-1])
        current_pos += file_name_length
        file_contents_length = to_int(packet_data[current_pos:current_pos+2])
        current_pos += 2
        file_contents = to_string(packet_data[current_pos:current_pos+file_contents_length-1])
        current_pos += file_contents_length
        if file_name == "display_name":
            return file_contents


def save_packet(packet_id, name, packet_data):
    filename = packet_id + '_' + name + '.pkt'
    if os.path.isfile(filename):
        return
    with open(filename, 'wb') as w:
        w.write(bytes.fromhex(''.join(packet_data[1:])))

with open(sys.argv[1], 'r') as f:
    packets = json.load(f)
    packet_data = []
    for packet in packets:
        packet_id = packet['_source']['layers']['frame']['frame.number'].zfill(len(str(len(packets))))
        if "btatt" not in packet['_source']['layers'].keys():
            continue
        if "btatt.handle" not in packet['_source']['layers']['btatt'].keys():
            continue
        if "btatt.opcode" not in packet['_source']['layers']['btatt'].keys():
            continue
        if "btatt.value" not in packet['_source']['layers']['btatt'].keys():
            continue
        if packet['_source']['layers']['btatt']['btatt.handle'] not in ["0x00000048", "0x0000004e"]:
            continue
        if packet['_source']['layers']['btatt']['btatt.opcode'] not in ["0x00000052", "0x0000001b", "0x00000012"]:
            continue
        data = packet['_source']['layers']['btatt']['btatt.value'].split(":")
        if not packet_data:
            packet_data = data
        else:
            packet_data.extend(data[1:])
        if packet['_source']['layers']['bthci_acl']['bthci_acl.pb_flag'] == "1" and packet['_source']['layers']['frame']['frame.len'] == "256":
            continue
        if len(data) == 509:
            continue
        if packet['_source']['layers']['bthci_acl']['bthci_acl.dst.bd_addr'].startswith("de:0c:40"):
            print("phone->watch: ", end="")
            from_phone = True
            from_watch = False
        if packet['_source']['layers']['bthci_acl']['bthci_acl.src.bd_addr'].startswith("de:0c:40"):
            print("watch->phone: ", end="")
            from_watch = True
            from_phone = False
        if "".join(packet_data[2:5]) == "090200":
            print("Notification packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            save_packet(packet_id, 'notification', packet_data)
            parse_header(packet_data)
            parse_notification(packet_data)
        elif "".join(packet_data[2:5]) == "150300":
            print("Watch app upload packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            watchapp_name = get_watchapp_name(packet_data)
            print(f"Watch app name: {watchapp_name}")
            save_packet(packet_id, 'watchapp_' + watchapp_name.lower(), packet_data)
            parse_header(packet_data)
        elif "".join(packet_data[2:5]) == "0c0200":
            print("Notification filter packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            save_packet(packet_id, 'notificationfilter', packet_data)
            parse_header(packet_data)
            parse_notification_filter(packet_data)
        elif "".join(packet_data[2:5]) == "130200":
            print("Quick replies configuration packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            save_packet(packet_id, 'quickreplies', packet_data)
            parse_header(packet_data)
            parse_quick_replies(packet_data)
        elif "".join(packet_data[2:5]) == "070200":
            print("Icons packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            save_packet(packet_id, 'icons', packet_data)
            parse_header(packet_data)
            parse_icons(packet_data)
        elif from_phone and "".join(packet_data[0:2]) == "007b":
            print("JSON packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            save_packet(packet_id, 'json', packet_data)
            print(to_string(packet_data[1:]))
            packet_data = []
        elif from_watch and "".join(packet_data[0:2]) == "0201":
            print("JSON packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            save_packet(packet_id, 'json', packet_data)
            print(to_string(packet_data[3:]))
            packet_data = []
        elif from_watch and packet_data[0] == "01" and packet_data[1] == "04":
            print("Phone call action packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            save_packet(packet_id, 'phonecall', packet_data)
            print(" ".join(packet_data) + ": ", end="")
            if packet_data[7] == "01":
                print("call started")
            elif packet_data[7] == "02":
                print("call dismissed")
            elif packet_data[7] == "03":
                print("quick reply " + packet_data[8] + " chosen")
            packet_data = []
        elif from_watch and "".join(packet_data[2:5]) == "150303":
            print("Installed apps list packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            parse_header(packet_data)
            parse_installed_apps(packet_data)
        elif from_phone and "".join(packet_data[2:5]) == "070214":
            print("Translations packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
            parse_header(packet_data)
        else:
            print("Unknown packet ({}):".format(packet['_source']['layers']['frame']['frame.number']))
        if len(packet_data) == 4:
            print("Footer")
            print(" ".join(pop_elements(packet_data, 4)) + " : file CRC")
        elif len(packet_data) > 0:
            print("handle=" + packet['_source']['layers']['btatt']['btatt.handle'] + " opcode=" + packet['_source']['layers']['btatt']['btatt.opcode'])
            print("Unrecognized bytes:")
            print(" ".join(packet_data))
        packet_data = []
        print()
