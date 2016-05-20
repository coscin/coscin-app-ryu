# l2_switch_handler

# Handles traffic between two hosts on the same side of the Coscin network, including a host
# and it's real router port (the default gateway).  It acts like a learning switch, but it
# only learns packets with IP source information so it can translate between port, mac and IP
# seemlessly.  Until an IP packet appears from a port, it handles all traffic from that port
# here in the controller - e.g. DHCP, etc.  That's OK because non-IP traffic is pretty light.  

from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, tcp
from openflow_utils import OpenflowUtils
from net_utils import NetUtils
from cross_campus_handler import CrossCampusHandler

class L2LearningSwitchHandler():
  LEARN_NEW_MACS_RULE = 1000
  LEARNED_MAC_TIMEOUT = 3600  # = 1 Hour

  def __init__(self, nib, logger):
    self.nib = nib
    self.logger = logger

  def arp_for_router(self, dp, switch):
    # Learning the router port is really important, so we send an ARP packet to poke it into submission
    # Note that host .2 may not or may not be a real host, but the reply will always come back to the switch anyway.
    target_ip_net = self.nib.actual_net_for(switch)
    src_ip = NetUtils.ip_for_network(target_ip_net, 2)
    dst_ip = NetUtils.ip_for_network(target_ip_net, 1)  # The IP of the router interface will always be a .1
    OpenflowUtils.send_arp_request(dp, src_ip, dst_ip)  

  def install_fixed_rules(self, dp):
    # Table 0, the Source Mac table, has table miss=Goto Controller so it can learn 
    # newly-connected macs
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    match_all = parser.OFPMatch()
    actions = [ parser.OFPActionOutput(ofproto.OFPP_CONTROLLER) ]
    OpenflowUtils.add_flow(dp, priority=0, match=match_all, actions=actions, table_id=0, cookie=self.LEARN_NEW_MACS_RULE)

    # Table 1, the Dest Mac table, has table-miss = Flood.  If the destination exists,
    # it'll send a reply packet that'll get learned in table 0.  We can afford to do a 
    # sloppy non-spanning-tree flood because there's only one switch in our topology
    actions = [ parser.OFPActionOutput(ofproto.OFPP_FLOOD) ]
    OpenflowUtils.add_flow(dp, priority=0, match=match_all, actions=actions, table_id=1)

    self.arp_for_router(dp, switch)

  def packet_in(self, msg):
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    in_port = msg.match['in_port']

    # Interesting packet data
    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    dst = eth.dst
    src = eth.src    

    # As stated before, we only learn from packets with IP source info in them.  
    if not self.nib.learned(src) and (eth.ethertype == ether_types.ETH_TYPE_IP or eth.ethertype == ether_types.ETH_TYPE_ARP):

      if eth.ethertype == ether_types.ETH_TYPE_IP:
        p_ip = pkt.get_protocols(ipv4.ipv4)[0]
        src_ip = p_ip.src
      elif eth.ethertype == ether_types.ETH_TYPE_ARP:
        p_arp = pkt.get_protocols(arp.arp)[0]
        src_ip = p_arp.src_ip

      match_mac_src = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_src = src )
      match_mac_dst = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_dst = src )

      target_ip_net = self.nib.actual_net_for(switch)
      if src_ip == NetUtils.ip_for_network(target_ip_net, 1):   # .1 is always the router
        # If this is coming from a router, we add goto table 2 rules in tables 0 and 1 instead.  
        # All packets to/from the router go through table 2 to rewrite IP addresses instead. (See cross_campus_handler)
        OpenflowUtils.add_goto_table(dp, priority=0, match=match_mac_src, goto_table_id=2, table_id=0)
        OpenflowUtils.add_goto_table(dp, priority=0, match=match_mac_dst, goto_table_id=2, table_id=1)

        self.nib.learn(switch, self.nib.ROUTER_PORT, in_port, src, src_ip)

        # We also install path learning rules for table 3.  Since this is the responsibility of
        # cross_campus_handler, it would be better if we installed them there, but I don't know quite
        # how to do it.

        # Incoming Packet Capture (e.g Coscin Ith->NYC on the Ith side), Cookie INCOMING_FLOW_RULE
        match = parser.OFPMatch( eth_dst = src, eth_type=ether_types.ETH_TYPE_IP )
        actions = [ parser.OFPActionOutput(ofproto.OFPP_CONTROLLER) ]
        OpenflowUtils.add_flow(dp, priority=65535, match=match, actions=actions, 
          table_id=3, cookie=CrossCampusHandler.INCOMING_FLOW_RULE)    

        # Outgoing Packet Capture (e.g. Coscin Ith->NYC on the NYC side), Cookie OUTGOING_FLOW_RULE
        match = parser.OFPMatch( eth_src = src, eth_type=ether_types.ETH_TYPE_IP )
        OpenflowUtils.add_flow(dp, priority=65534, match=match, actions=actions, 
          table_id=3, cookie=CrossCampusHandler.OUTGOING_FLOW_RULE)  

      # We don't learn any hosts until we've learned the router.  Otherwise IP packets from the other
      # side of the switch might be learned as the router port.  Send another request just in case it missed
      # the first one.  

      elif self.nib.router_port_for_switch(switch) == None:
        self.arp_for_router(dp, switch)

      else:
        # The packet is from a host, not a router.  A new packet carries information on the mac address, 
        # which we turn into a GOTO-table 1 rule in table 0
        OpenflowUtils.add_goto_table(dp, priority=65535, match=match_mac_src, goto_table_id=1, table_id=0)

        # And a send-to-port instruction for a destination match in table 1
        actions = [ parser.OFPActionOutput(in_port) ]
        OpenflowUtils.add_flow(dp, priority=0, match=match_mac_dst, actions=actions, table_id=1)

        # Learn it for posterity 
        self.nib.learn(switch, self.nib.ENDHOST_PORT, in_port, src, src_ip)

    # Don't send the packet out here if it's coming to/from a router.  
    # Those will be handled by cross_campus_handler, which may rewrite IP's as well.
    cookie = msg.cookie
    if cookie == CrossCampusHandler.INCOMING_FLOW_RULE or cookie == CrossCampusHandler.OUTGOING_FLOW_RULE:
      return

    # Now we have to deal with the Mac destination.  If we know it already, send the packet out that port.
    # Otherwise flood it.   
    output_p = self.nib.port_for_mac(dst)
    if output_p == None:
      output_p = ofproto.OFPP_FLOOD

    out_data = msg.data if msg.buffer_id == 0xffffffff else None 
    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
      in_port=in_port, actions=[ parser.OFPActionOutput(output_p) ], data=out_data)
    dp.send_msg(out)

  def port_status(self, msg):
    port = msg.desc.port_no
    dp = msg.datapath
    switch = self.nib.switch_for_dp(dp)
    parser = dp.ofproto_parser
    ofp = dp.ofproto

    # We ignore any status messages coming from the Router port because they cause too much 
    # catastrophe to unlearn.  If you ever change the router port, you must restart this app.  
    if port != self.nib.router_port_for_switch(switch):
      # We actually don't care what modification has happened to the port - could be LinkUp, could
      # be LinkDown, whatever.  We unlearn the port, remove any table 0 or 1 rules, and let it relearn
      self.logger.info("Port "+str(port)+" changed status.  Removing L2 rules, if any.")
      # First lookup the mac
      mac = self.nib.mac_for_port(switch, port)
      if mac != None:
        # Remove source and destination rules with that Mac
        match_mac_src = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_src = mac )
        match_mac_dst = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_dst = mac )
        m = parser.OFPFlowMod(dp, 0, 0, 0, ofp.OFPFC_DELETE, 0, 0, 1,
          ofp.OFPCML_NO_BUFFER, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, match_mac_src, instructions=[])
        dp.send_msg(m)        
        m = parser.OFPFlowMod(dp, 0, 0, 1, ofp.OFPFC_DELETE, 0, 0, 1,
          ofp.OFPCML_NO_BUFFER, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, match_mac_dst, instructions=[])
        dp.send_msg(m)        

        # And unlearn it
        self.nib.unlearn(switch, port)
