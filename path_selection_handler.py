# path_selection_hander
# Listen for any packets with the special ethertype 0x808.  Read utilization stats out of it
# and set the preferred path accordingly.  All subsequent new flows in cross_campus_handler
# will use this updated preferred path 

from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, tcp
from openflow_utils import OpenflowUtils
from net_utils import NetUtils
from coscin_utilization_data import CoscinUtilizationData

class PathSelectionHandler():

  def __init__(self, nib, logger):
    self.nib = nib
    self.logger = logger

  def install_fixed_rules(self, dp):
    # No rules.  The utilization NIC will send a packet with Ethernet type 0x88, and the L2
    # learning switch will prevent it from being learned because its not Ip/Arp.  
    # Thus all packets will come to this handler
    pass

  def packet_in(self, msg):
    # If IP rewriting is not on, the Path Selection handler does nothing
    if not self.nib.ip_rewriting():
      return

    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    in_port = msg.match['in_port']

    # Interesting packet data
    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]

    if eth.ethertype == CoscinUtilizationData.COSCIN_PROTOCOL:
      # The data will be n one-byte integers, utilization numbers for each path.  Parse it out.
      cpd = pkt.get_protocols(CoscinUtilizationData)[0]
      self.logger.info("Utilization data: "+str(cpd.util1)+","+str(cpd.util2)+","+str(cpd.util3))

      # This is admittedly stupid, but for three paths, who cares?
      if cpd.util1 < cpd.util2 and cpd.util1 < cpd.util3:
        selected_path = 1
      elif cpd.util2 < cpd.util1 and cpd.util2 < cpd.util3:
        selected_path = 2
      else:
        selected_path = 3

      self.nib.set_preferred_path(selected_path - 1)
      self.logger.info("Set preferred path to "+str(selected_path))