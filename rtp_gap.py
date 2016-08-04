from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
from pcapfile.protocols.transport import udp
import binascii
import rtp
import sys


if len(sys.argv) < 2:
  print "Usage: python rtp_gap.py <pcap>\n"

capfile = savefile.load_savefile(open(sys.argv[1], 'rb'), verbose=False)

last_seq = 0
in_gap   = False

for packet in capfile.packets:
  eth_frame = ethernet.Ethernet(packet.raw())

  # Is it IP?
  if eth_frame.type == 0x0800:
    ip_packet = ip.IP(binascii.unhexlify(eth_frame.payload))

    # Is it UDP?
    if ip_packet.p == 17:
      udp_packet = udp.UDP(binascii.unhexlify(ip_packet.payload))

      # Simple RTP identification heuristic
      if (udp_packet.dst_port > 16383 or
           udp_packet.src_port > 16383 and
           not udp_packet.dst_port & 1):
        rtp_pkt = rtp.RTP(binascii.unhexlify(udp_packet.payload))
        if rtp_pkt.seq != (last_seq + 1) & 0xFFFF:
          print "GAP in SSRC: %x from seq: %u to seq: %u" % (rtp_pkt.ssrc,
          last_seq, rtp_pkt.seq)
        last_seq = rtp_pkt.seq          


