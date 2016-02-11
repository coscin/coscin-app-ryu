from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from openflow_utils import OpenflowUtils
from net_utils import NetUtils

class CrossCampusHandler():
  INCOMING_FLOW_RULE = 2000
  OUTGOING_FLOW_RULE = 2001

  def __init__(self, nib, logger):
    self.nib = nib
    self.logger = logger

  def install_fixed_rules(self):
    # The capture rules can only be installed once we learn the router port and mac, so they get installed
    # in l2_learning_switch_handler.  
    pass

  def add_outgoing_dynamic_flow(self, msg):
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    in_port = msg.match['in_port']

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    ip = pkt.get_protocols(ipv4.ipv4)[0]

    # Only TCP and UDP packets can be handled by installing rules in custom pipleine hash table.  Handle
    # all other IP protocols (like ICMP) by acting like an L2 switch.  The traffic on these protocols 
    # should be light enough to handle all by controller.  
    if ip.proto != 0x6 and ip.proto != 0x11:
      return [ parser.OFPActionOutput(self.nib.router_port_for_switch(switch)) ]

    src_ip = ip.src
    dst_ip = ip.dst

    actions = [ ]

    if self.nib.ip_in_coscin_network(dst_ip):
      opposite_switch = self.nib.opposite_switch(switch)
      # If this is bound for the "virtual" network on the other side, pick the path and rewrite
      # the destination IP's
      if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(opposite_switch)):
        # Get host from src_ip
        src_pref_net = self.nib.preferred_net(switch)
        src_host = NetUtils.host_of_ip(src_ip, self.nib.actual_net_for(switch))
        # Translate this to the preferred path IP
        new_src = NetUtils.ip_for_network(src_pref_net, src_host)
        actions.append( parser.OFPActionSetField(ipv4_src=new_src) )
        # And do the same for the destination
        dest_host = NetUtils.host_of_ip(dst_ip, self.nib.actual_net_for(opposite_switch))
        new_dest = NetUtils.ip_for_network(self.nib.preferred_net(opposite_switch), dest_host)
        actions.append( parser.OFPActionSetField(ipv4_dst=new_dest) )
      else:
        for ap in self.nib.alternate_paths():
          if NetUtils.ip_in_network(dst_ip, ap[opposite_switch]):
            src_net = ap[switch] 

        src_host = NetUtils.host_of_ip(src_ip, self.nib.actual_net_for(switch))
        # Translate this to the direct path IP
        new_src = NetUtils.ip_for_network(src_net, src_host)        
        actions.append( parser.OFPActionSetField(ipv4_src=new_src) )

    # No matter what, we always send the packet to the router
    actions.append(parser.OFPActionOutput(self.nib.router_port_for_switch(switch)))

    match = parser.OFPMatch(
      ipv4_src=ip.src
      ,ipv4_dst=ip.dst
      ,eth_type=0x0800
      ,ip_proto=ip.proto  
      ,vlan_vid=self.nib.vlan_for_switch(switch)
    )
    if ip.proto == 0x6:
      tcp_pkt = pkt.get_protocols(tcp.tcp)[0]
      match.set_tcp_src( tcp_pkt.src_port )
      match.set_tcp_dst( tcp_pkt.dst_port )
    elif ip.proto == 0x11:
      udp_pkt = pkt.get_protocols(udp.udp)[0]
      match.set_udp_src( udp_pkt.src_port )
      match.set_udp_dst( udp_pkt.dst_port )

    # The flow will naturally age out after 10 minutes of idleness.  That way we can pick a new path for
    # it if it starts up again.
    OpenflowUtils.add_flow(dp, priority=0, match=match, actions=actions, table_id=2, idle_timeout=600)
    self.logger.error("Added outgoing hash rule for "+str(ip.src)+":" + str(tcp_pkt.src_port) +  " -> "+
      str(ip.dst) +":" + str(tcp_pkt.dst_port)
    )

    return actions

  def add_incoming_dynamic_flow(self, msg):
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    in_port = msg.match['in_port']

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    ip = pkt.get_protocols(ipv4.ipv4)[0]

    # See discussion about non-TCP and non-UDP traffic above.  Note that this side is different in that
    # we don't necessarily know the port, so just handle like an L2 switch    
    if ip.proto != 0x6 and ip.proto != 0x11:
      output_p = self.nib.port_for_mac(eth.dst)
      if output_p == None:
        output_p = ofproto.OFPP_FLOOD
      return [ parser.OFPActionOutput(output_p) ]

    src_ip = ip.src
    dst_ip = ip.dst

    # This could happen if the other side of the network is not properly rewriting the destination.
    if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
      output_p = self.nib.port_for_mac(dst)
      if output_p == None:
        output_p = ofproto.OFPP_FLOOD
      return [ parser.OFPActionOutput(output_p) ]

    for ap in self.nib.alternate_paths():
      if NetUtils.ip_in_network(dst_ip, ap["ithaca"]): 
        switch = "ithaca" 
        imaginary_net = ap["ithaca"]
      elif NetUtils.ip_in_network(dst_ip, ap["nyc"]):
        switch = "nyc"
        imaginary_net = ap["nyc"]
    real_net = self.nib.actual_net_for(switch)
    dst_host = NetUtils.host_of_ip(dst_ip, imaginary_net)
    new_dest_ip = NetUtils.ip_for_network(real_net, dst_host)

    # If the ip hasn't yet been learned yet, just flood it out to all ports without installing a rule.  The 
    # recipient should naturally reply, causing learning to occur, and the next packet will install the rule.  
    if not self.nib.learned_ip(new_dest_ip):
      return [ parser.OFPActionOutput(ofproto.OFPP_FLOOD) ]

    direct_net_port = self.nib.port_for_ip(new_dest_ip)
    new_src_ip = self.nib.translate_alternate_net(src_ip)    

    match = parser.OFPMatch(
      ipv4_src=ip.src
      ,ipv4_dst=ip.dst
      ,eth_type=0x0800
      ,ip_proto=ip.proto  
      ,vlan_vid=self.nib.vlan_for_switch(switch)
    )
    if ip.proto == 0x6:
      tcp_pkt = pkt.get_protocols(tcp.tcp)[0]
      match.set_tcp_src( tcp_pkt.src_port )
      match.set_tcp_dst( tcp_pkt.dst_port )
    elif ip.proto == 0x11:
      udp_pkt = pkt.get_protocols(udp.udp)[0]
      match.set_udp_src( udp_pkt.src_port )
      match.set_udp_dst( udp_pkt.dst_port )

    actions = [
      parser.OFPActionSetField(ipv4_src=new_src_ip),
      parser.OFPActionSetField(ipv4_dst=new_dest_ip),
      parser.OFPActionOutput(direct_net_port)
    ]
    # The flow will naturally age out after 10 minutes of idleness.  That keeps the table clean.
    OpenflowUtils.add_flow(dp, priority=0, match=match, actions=actions, table_id=2, idle_timeout=600)
    self.logger.error("Added incoming hash rule for "+str(ip.src)+":" + str(tcp_pkt.src_port) +  " -> "+
      str(ip.dst) +":" + str(tcp_pkt.dst_port)
    )

    return actions

  def packet_in(self, msg):
    # We're only interested in packets bound or coming from the router
    cookie = msg.cookie
    actions = None
    if cookie == self.INCOMING_FLOW_RULE:
      actions = self.add_outgoing_dynamic_flow(msg)
    elif cookie == self.OUTGOING_FLOW_RULE:
      actions = self.add_incoming_dynamic_flow(msg)

    # If we got some actions, actually apply them to send the packet out
    if actions != None:
      dp = msg.datapath
      parser = dp.ofproto_parser
      in_port = msg.match['in_port']

      out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
      dp.send_msg(out)
