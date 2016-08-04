from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import udp
from collections import defaultdict
import binascii
import rtp
import sys

# Tested with Python 2.7 and pypcapfile 0.11.1


def get_udp_packet(raw_packet):
    eth_frame = ethernet.Ethernet(raw_packet)

    # Is it IP?
    if eth_frame.type == 0x0800:
        ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))

        # Is it UDP?
        if ip_packet.p == 17:
            return udp.UDP(binascii.unhexlify(ip_packet.payload))

def is_rtp(udp_packet):
    if udp_packet is not None and (
            udp_packet.dst_port > 16383 or
            udp_packet.src_port > 16383 and
            not udp_packet.dst_port & 1
    ):
        return True
    else:
        return False

def print_gaps(capfile):
    last_seqs = defaultdict(int)
    for packet in capfile.packets:
        udp_packet = get_udp_packet(packet.raw())

        if is_rtp(udp_packet):
            rtp_pkt = rtp.RTP(binascii.unhexlify(udp_packet.payload))

            last_seq = last_seqs[rtp_pkt.ssrc]

            if rtp_pkt.seq != ((last_seq + 1) & 0xFFFF) and rtp_pkt.seq != last_seq:
                print "GAP in SSRC: %x from seq: %u to seq: %u" % (
                    rtp_pkt.ssrc, last_seq, rtp_pkt.seq
                )


            last_seqs[rtp_pkt.ssrc] = rtp_pkt.seq

def load_capfile(filename):
    with open(filename, 'rb') as raw_file:
        capfile = savefile.load_savefile(raw_file, verbose=False)

    return capfile


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit("Usage: python rtp_gap.py <pcap>\n")

    capfile = load_capfile(sys.argv[1])
    print_gaps(capfile)
