from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp
from openflow_utils import OpenflowUtils
from net_utils import NetUtils

class CrossCampusHandler():

  def __init__(self, nib, logger):
    self.nib = nib
    self.logger = logger

  def install_fixed_rules(self):
    # TODO: We'll learn the router interfaces by learning them in a later version.  For now, just hard code.
    for switch in self.nib.switches_present():
      dp = self.nib.dp_for_switch(switch)
      ofproto = dp.ofproto
      parser = dp.ofproto_parser

      router_mac = self.nib.router_mac_for_switch(switch)
      # Packets coming in from the router go to Table 2
      match_mac = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_src = router_mac )
      inst = [ parser.OFPInstructionGotoTable(2) ]
      mod = parser.OFPFlowMod(datapath=dp, priority=0,
        cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        flags=ofproto.OFPFF_SEND_FLOW_REM, match=match_mac, instructions=inst, table_id=0)
      dp.send_msg(mod)

      # Packets going out to the router go to Table 2 as well
      match_mac = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_dst = router_mac )
      mod = parser.OFPFlowMod(datapath=dp, priority=0,
        cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        flags=ofproto.OFPFF_SEND_FLOW_REM, match=match_mac, instructions=inst, table_id=1)
      dp.send_msg(mod)

      # This prevents the router port from being learned on its own, and overwriting the rule above.
      self.nib.learn(switch, self.nib.ROUTER_PORT, 1, router_mac)

      # These actually ARE NOT hard-coding, and will be left in.  They're catch-alls for new flows.

      # Ingress Packet Capture, Cookie 2000
      match = parser.OFPMatch(eth_dst = router_mac ,eth_type=0x0800 )
      actions = [ parser.OFPActionOutput(ofproto.OFPP_CONTROLLER) ]
      OpenflowUtils.add_flow(dp, priority=65535, match=match, actions=actions, table_id=3, cookie=2000)    

      # Egress Packet Capture, Cookie 2001
      match = parser.OFPMatch(eth_src = router_mac ,eth_type=0x0800 )
      OpenflowUtils.add_flow(dp, priority=65534, match=match, actions=actions, table_id=3, cookie=2001)          

  def add_outgoing_dynamic_flow(self, msg):
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    in_port = msg.match['in_port']

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]

    # This shouldn't happen because nics don't send non-IP packets to a router
    if eth.ethertype != 0x800:
      self.logger.error("Non IP packet sent to a router.  Ignored.")
      return

    ip = pkt.get_protocols(ipv4.ipv4)[0]

    # TODO: Handle UDP as well
    if ip.proto != 0x6:
      self.logger.error("Non TCP packet ignored for now")
      return

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

    tcp_pkt = pkt.get_protocols(tcp.tcp)[0]

    match = parser.OFPMatch(
      ipv4_src=ip.src
      ,ipv4_dst=ip.dst
      ,eth_type=0x0800
      ,ip_proto=ip.proto  
      ,tcp_src=tcp_pkt.src_port
      ,tcp_dst=tcp_pkt.dst_port
      ,vlan_vid=self.nib.vlan_for_switch(switch)
    )
    # The flow will naturally age out after 10 minutes of idleness.  That way we can pick a new path for
    # it if it starts up again.
    OpenflowUtils.add_flow(dp, priority=0, match=match, actions=actions, table_id=2, idle_timeout=600)
    self.logger.error("Added outgoing hash rule for "+str(ip.src)+":" + str(tcp_pkt.src_port) +  " -> "+
      str(ip.dst) +":" + str(tcp_pkt.dst_port)
    )

    # Send packet to the router, and make it do the same actions the rule would've done.
    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
      in_port=in_port, actions=actions, data=msg.data)
    dp.send_msg(out)

  def add_incoming_dynamic_flow(self, msg):
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    in_port = msg.match['in_port']

    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]

    # This shouldn't happen because a router doesn't send non-IP packets to hosts.
    if eth.ethertype != 0x800:
      self.logger.error("Non IP packet sent from a router.  Ignored.")
      return

    ip = pkt.get_protocols(ipv4.ipv4)[0]

    # TODO: Handle UDP as well
    if ip.proto != 0x6:
      self.logger.error("Non TCP packet ignored for now")
      return

    src_ip = ip.src
    dst_ip = ip.dst

    # Convert dst_ip to its real form.  First find out what the egress switch actually is:
    self.logger.info("Packet for "+str(src_ip) +" -> "+ str(dst_ip))

    # I'm getting these issues if the rewrites are not properly happening.
    if NetUtils.ip_in_network(dst_ip, self.nib.actual_net_for(switch)):
      self.logger.info("This shouldn't be happening.  Packet should be coming from virtual net.  Outputting packet.")
      out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
        in_port=1, actions=[ parser.OFPActionOutput(2) ], data=msg.data)
      dp.send_msg(out)
      return


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

    # If it's not in the ARP cache, it already has an ARP request on the way so ignore it for now.
    # TODO: We don't have a learning table for IP's yet.  But we will.  
    #if not self.nib.learned_ip(new_dest_ip):
    #  return

    #direct_net_port = self.nib.port_for_ip(new_dest_ip)
    direct_net_port = 2
    new_src_ip = self.nib.translate_alternate_net(src_ip)    

    tcp_pkt = pkt.get_protocols(tcp.tcp)[0]

    match = parser.OFPMatch(
      ipv4_src=ip.src
      ,ipv4_dst=ip.dst
      ,eth_type=0x0800
      ,ip_proto=ip.proto  
      ,tcp_src=tcp_pkt.src_port
      ,tcp_dst=tcp_pkt.dst_port
      ,vlan_vid=self.nib.vlan_for_switch(switch)
    )
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

    # Send packet to the host, and make it do the same actions the rule would've done.
    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
      in_port=in_port, actions=actions, data=msg.data)
    dp.send_msg(out)


  def packet_in(self, msg):
    # We're only interested in packets bound or coming from the router
    cookie = msg.cookie
    if cookie == 2000:
      self.add_outgoing_dynamic_flow(msg)
    elif cookie == 2001:
      self.add_incoming_dynamic_flow(msg)

