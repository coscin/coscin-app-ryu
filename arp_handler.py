# arp_handler
# Reply to ARP requests for imaginary networks.  These requests get sent by the routers.  For the example
# outlined in cross_campus_handler, the router might send an ARP request for 192.168.157.200.  This 
# handler picks it up and sends a reply with the Mac for 57.200 (if it's known) 

from ryu.lib.packet import packet, ethernet, ether_types, arp
from openflow_utils import OpenflowUtils
from net_utils import NetUtils

class ArpHandler():
  ARP_RULE = 3000

  def __init__(self, nib, logger):
    self.nib = nib
    self.logger = logger

  def install_fixed_rules(self, dp):

    # We grab all ARP requests and replies.  You can't match with any more granularity 
    # than that on HP's custom pipleine, unfortunately.  
    ofproto = dp.ofproto
    parser = dp.ofproto_parser

    match_arp = parser.OFPMatch( eth_type=ether_types.ETH_TYPE_ARP )
    actions = [ parser.OFPActionOutput(ofproto.OFPP_CONTROLLER) ]
    OpenflowUtils.add_flow(dp, priority=50, match=match_arp, actions=actions, table_id=3, cookie=self.ARP_RULE)

  def packet_in(self, msg):
    cookie = msg.cookie
    # Ignore all packets that came here by other rules than the ARP rule
    if cookie != self.ARP_RULE:
      return

    dp = msg.datapath

    pkt = packet.Packet(msg.data)
    p_eth = pkt.get_protocols(ethernet.ethernet)[0]
    p_arp = pkt.get_protocols(arp.arp)[0]
    src_ip = p_arp.src_ip
    dst_ip = p_arp.dst_ip
    switch = self.nib.switch_for_dp(dp)
    in_port = msg.match['in_port']

    # We only handle ARP requests for the virtual net here.  All ARP replies and requests were
    # actually forwarded by l2_switch_handler, but no one will answer those for the virtual net.
    # We formulate ARP responses for those requests here.

    if p_arp.opcode == arp.ARP_REQUEST:
      # Translate virtual address to a real one
      real_dest_ip = self.nib.translate_ip(dst_ip, self.nib.actual_net_for(switch)) 

      if real_dest_ip == None:
        pass
      elif self.nib.learned_ip(real_dest_ip):
        real_dest_mac = self.nib.mac_for_ip(real_dest_ip)
        OpenflowUtils.send_arp_reply(dp, in_port, p_eth.src, src_ip, real_dest_mac, dst_ip)
      else:
        # Send an ARP request to all ports, then just stay out of the way.  If the host is up
        # on an unlearned port, it'll send a response, and that'll trigger learning.  Then
        # when the NEXT ARP request for this address is received (it'll get retried a bunch of
        # times in practice), the reply can be generated from the ARP cache.  
        # It doesn't matter so much where the ARP reply goes, because this switch will pick it up.
        switch_net = self.nib.actual_net_for(switch)
        src_ip = NetUtils.ip_for_network(switch_net, 2)
        OpenflowUtils.send_arp_request(dp, src_ip, real_dest_ip)    

