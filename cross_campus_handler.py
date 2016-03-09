# Handles Coscin Traffic from NYC to Ithaca or Vice-Versa.  If the destinations uses an 
# "imaginary" destination address, choose the path explicitly.  If it uses a "real"
# destination address, choose the current preferred path.  So in our test network, if
# 192.168.56.100 is FTP'ing to 192.168.57.200 (both "real" networks), the IP's get rewritten
# to one of the paths below, basically encoding the best path in the IP addresses.

#    Host: 192.168.56.100      --->   192.168.57.200
#    BECOMES      (192.168.156.100)   --->   (192.168.157.200)
#              OR (192.168.158.100)   --->   (192.168.159.200)
#              OR (192.168.160.100)   --->   (192.168.161.200)

# The path lasts for the duration of the TCP/UDP flow using timeouts in table 2.   

from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, in_proto
from openflow_utils import OpenflowUtils
from net_utils import NetUtils

class CrossCampusHandler():
  OUTGOING_FLOW_RULE = 2001  # Cross-campus packet on the source side of the router
  INCOMING_FLOW_RULE = 2000  # Cross-campus packet on the target side of the router

  IDLE_TIMEOUT = 600 # = 10 minutes

  def __init__(self, nib, logger):
    self.nib = nib
    self.logger = logger

  def install_fixed_rules(self, dp):
    # The capture rules can only be installed once we learn the router port and mac, so they get installed
    # in l2_learning_switch_handler.  
    pass

  # The rules that we write for incoming and outgoing packets looks a lot alike - just the actions
  # are different.    
  def write_table_2_rule(self, switch, dp, ip, pkt, actions, direction ):
    parser = dp.ofproto_parser
    if ip.proto == in_proto.IPPROTO_TCP:  
      tcp_pkt = pkt.get_protocols(tcp.tcp)[0]
      match = parser.OFPMatch(
        ipv4_src=ip.src
        ,ipv4_dst=ip.dst
        ,eth_type=ether_types.ETH_TYPE_IP
        ,ip_proto=ip.proto  
        ,vlan_vid=self.nib.vlan_for_switch(switch)
        ,tcp_src = tcp_pkt.src_port
        ,tcp_dst = tcp_pkt.dst_port
      )
      src_port = tcp_pkt.src_port
      dst_port = tcp_pkt.dst_port
    elif ip.proto == in_proto.IPPROTO_UDP:
      udp_pkt = pkt.get_protocols(udp.udp)[0]
      match = parser.OFPMatch(
        ipv4_src=ip.src
        ,ipv4_dst=ip.dst
        ,eth_type=ether_types.ETH_TYPE_IP
        ,ip_proto=ip.proto  
        ,vlan_vid=self.nib.vlan_for_switch(switch)
        ,udp_src = udp_pkt.src_port
        ,udp_dst = udp_pkt.dst_port
      )
      src_port = udp_pkt.src_port
      dst_port = udp_pkt.dst_port

    # The flow will naturally age out after 10 minutes of idleness.  That way we can pick a new path for
    # it if it starts up again.
    OpenflowUtils.add_flow(dp, priority=0, match=match, actions=actions, table_id=2, idle_timeout=self.IDLE_TIMEOUT)
    self.logger.info("Added "+direction+" hash rule for "+str(ip.src)+":" + str(src_port) +  " -> "+
      str(ip.dst) +":" + str(dst_port)
    )

  # When we see a flow (basically a 5-tuple: src_ip, dst_ip, protocol, src_port, dst_port), 
  # we add an outgoing rule on the source side of the flow.  
  def add_outgoing_dynamic_flow(self, msg):
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    in_port = msg.match['in_port']

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    ip = pkt.get_protocols(ipv4.ipv4)[0]
    src_ip = ip.src
    dst_ip = ip.dst

    actions = [ ]

    # We only add IP rewriting for Coscin packets.  All non-coscin packets will get a flow rule, but no
    # IP rewriting.  
    if self.nib.ip_rewriting() and self.nib.ip_in_coscin_network(dst_ip):
      opposite_switch = self.nib.opposite_switch(switch)
      # If this is bound for the "virtual" network on the other side, pick the path and rewrite
      # the destination IP's
      if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(opposite_switch)):
        new_src_ip = self.nib.translate_ip(src_ip, self.nib.preferred_net(switch))
        actions.append( parser.OFPActionSetField( ipv4_src = new_src_ip ) )

        new_dst_ip = self.nib.translate_ip(dst_ip, self.nib.preferred_net(opposite_switch))
        actions.append( parser.OFPActionSetField( ipv4_dst = new_dst_ip ) )
      else:
        # If it's a direct route (e.g 56.100 -> 157.200), we only need to renumber the source. 
        # But we have to select the right imaginary net so the path is "straight" 
        new_src_ip = self.nib.translate_ip(src_ip, self.nib.opposite_net_for(dst_ip))
        actions.append( parser.OFPActionSetField( ipv4_src = new_src_ip ) )

    # No matter what, our rule will always send the packet to the router
    actions.append(parser.OFPActionOutput(self.nib.router_port_for_switch(switch)))

    # Only TCP and UDP packets are handled by installing rules in custom pipleine hash table. 
    # (But we had to compute the actios regardless because they'll be used in a Packet Out)
    if ip.proto == in_proto.IPPROTO_TCP or ip.proto == in_proto.IPPROTO_UDP:
      self.write_table_2_rule(switch, dp, ip, pkt, actions, "outgoing" )

    return actions

  # This installs a rule for the "opposite" side of the network.  When it reaches this point, 
  # we know the destination IP is either the real network of this switch, or one
  # virtual network.  The source may be as well.  When we're done, there should only be real
  # networks in both the source and dest.

  def add_incoming_dynamic_flow(self, msg):
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    ip = pkt.get_protocols(ipv4.ipv4)[0]
    src_ip = ip.src
    dst_ip = ip.dst

    # If the destination IP is in the real network (ip_in_network returns true), 
    # then the other side of the network is not properly rewriting the destination.
    # or the packet is coming from the non-Coscin Internet.  Just leave those IP's alone (we assume 
    # there's nothing crazy like the source using a virtual address here.)
    actions = []
    if self.nib.ip_rewriting() and not NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
      opposite_switch = self.nib.opposite_switch(switch)

      new_src_ip = self.nib.translate_ip(src_ip, self.nib.actual_net_for(opposite_switch))    
      actions.append( parser.OFPActionSetField(ipv4_src=new_src_ip) )

      new_dst_ip = self.nib.translate_ip(src_ip, self.nib.actual_net_for(switch))    
      actions.append( parser.OFPActionSetField(ipv4_dst=new_dst_ip) )

    # The destination mac in the packet is guaranteed OK because the router placed it there as a result
    # of its ARP cache.  However, that doesn't necessarily mean we have learned that port yet, so act like
    # an L2 switch.  But in that case, don't install the rule because we don't want to just flood the switch
    # everytime it happens.  
    output_p = self.nib.port_for_mac(eth.dst)
    if output_p == None:
      output_p = ofproto.OFPP_FLOOD
    actions.append(parser.OFPActionOutput(output_p))

    if (ip.proto == in_proto.IPPROTO_TCP or ip.proto == in_proto.IPPROTO_UDP) and output_p != ofproto.OFPP_FLOOD:
      self.write_table_2_rule(switch, dp, ip, pkt, actions, "incoming" )

    return actions

  def packet_in(self, msg):
    # We're only interested in packets bound or coming from the router
    cookie = msg.cookie
    actions = None
    if cookie == self.INCOMING_FLOW_RULE:
      actions = self.add_outgoing_dynamic_flow(msg)
    elif cookie == self.OUTGOING_FLOW_RULE:
      actions = self.add_incoming_dynamic_flow(msg)

    # If we got some actions, actually apply them to send the packet out.  Note this handles
    # all other IP protocols (like ICMP) by acting like an L2 switch.  The traffic on these protocols 
    # should be light enough to handle all by controller.  
    if actions != None:
      dp = msg.datapath
      parser = dp.ofproto_parser
      in_port = msg.match['in_port']

      out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
      dp.send_msg(out)
