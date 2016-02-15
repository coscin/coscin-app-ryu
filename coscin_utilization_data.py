# Coscin Utilization Packet Parser 
# Note we don't include a serializer here because we don't create any of these packets.
# The packet structure is really simple, just an Ethernet frame with ethertype 0x808, and 
# three bytes in the payload, each a number from 0-255 expressing relative utlization.  

import struct
from ryu.lib.packet import packet_base

class CoscinUtilizationData(packet_base.PacketBase):

  COSCIN_PROTOCOL = 0x808
  _PACK_STR = '!BBB'
  _MIN_LEN = struct.calcsize(_PACK_STR)

  def __init__(self, util1, util2, util3):
    self.util1 = util1
    self.util2 = util2
    self.util3 = util3

  @classmethod
  def parser(cls, buf):
    (util1, util2, util3) = struct.unpack_from(cls._PACK_STR, buf)
    return cls(util1, util2, util3), cls._TYPES.get(cls.COSCIN_PROTOCOL), buf[CoscinUtilizationData._MIN_LEN:]

CoscinUtilizationData.register_packet_type(CoscinUtilizationData, CoscinUtilizationData.COSCIN_PROTOCOL)