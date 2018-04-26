import argparse
import os
from scapy.all import *
import struct

OPERATIONS = {0: 'read', 1: 'write'}

def extract_pcap(target, pcap, output_dir):
    target_ip, target_port = target.split(":")
    target_port = int(target_port)
    print "Extracting packets involving %s:%d." % (target_ip, target_port)

    pcap_file = rdpcap(pcap)
    print "PCAP file '%s' parsed." % pcap

    if os.path.exists(output_dir):
        print "Output directory exists! Please choose another location."
        return

    os.mkdir(output_dir)
    print "Output directory '%s' created." % output_dir

    current_index = 0
    directions = []
    for pkt in pcap_file:
        direction = -1
        if Raw in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            if src_ip == target_ip and src_port == target_port:
                direction = 1
            if dst_ip == target_ip and dst_port == target_port:
                direction = 0

            if direction != -1:
                payload = pkt[Raw].load
                file_name = "%s/%s.data" % (output_dir, current_index)
                with open(file_name, 'w') as payload_file:
                    payload_file.write(payload)
                directions.append(direction)
                print "[%d] Target %s of %d bytes found." % (
                        current_index, OPERATIONS[direction], len(payload)
                        )
                current_index += 1

    assert(current_index == len(directions))
    with open("%s/packets.meta" % output_dir, 'w') as meta_file:
        meta_file.write(struct.pack("<I", current_index))
        for i in directions:
            meta_file.write(chr(i))
    print "Successfully written packet meta file of %d entries." % (
            current_index)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP address and port (e.g. 127.0.0.1:5000) of the target application.")
    parser.add_argument("pcap", help="PCAP file to parse.")
    parser.add_argument("-o", "--output", default="packets", help="Directory to output to.")
    args = parser.parse_args()

    extract_pcap(args.target, args.pcap, args.output)

if __name__ == "__main__":
    main()
