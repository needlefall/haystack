import binascii
import ctypes
import struct

class RTP(ctypes.Structure):

  _fields_ = [('flags', ctypes.c_ubyte),      # Flags
              ('mpt',   ctypes.c_ubyte),      # Marker + Payload Type
              ('seq',   ctypes.c_ushort),     # Sequence Number
              ('ts',    ctypes.c_ulong),      # Timestamp
              ('ssrc',  ctypes.c_ulong)]      # Sync Source
                
  rtp_header_size = 12

  def __init__(self, packet):
    fields = struct.unpack("!BBHII", packet[:self.rtp_header_size])
    self.flags  = fields[0]
    self.marker = fields[1] & 0x1
    self.pt     = (fields[1] & 0xFE) << 1 
    self.seq    = fields[2]
    self.ts     = fields[3]
    self.ssrc   = fields[4]
    self.payload = ctypes.c_char_p(binascii.hexlify(packet[self.rtp_header_size:]))


  def __str__(self):
    packet = 'RTP packet PT=%u SEQ=%u TS=%u SSRC=%x'
    packet = packet % (self.pt, self.seq, self.ts, self.ssrc)
    return packet

