from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, tcp
from openflow_utils import OpenflowUtils
from net_utils import NetUtils

class L2LearningSwitchHandler():
  LEARN_NEW_MACS_RULE = 1000

  def __init__(self, nib):
    self.nib = nib

  def install_fixed_rules(self):
    # Table 0, the Source Mac table, has Goto Controller for a table miss so it can learn 
    # newly-connected macs
    for switch in self.nib.switches_present():
      dp = self.nib.dp_for_switch(switch)
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

      # Learning the router port is really important, so we send an ARP packet to poke it
      # Note this may not or may not be a real host, but the reply will always come back to the switch anyway.
      target_ip_net = self.nib.actual_net_for(switch)
      src_ip = NetUtils.ip_for_network(target_ip_net, 2)
      dst_ip = NetUtils.ip_for_network(target_ip_net, 1)  # The IP of the router interface will always be a .1
      OpenflowUtils.send_arp_request(dp, src_ip, dst_ip)  

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

    # Don't re-add the mac if it's already been learned.  TODO: Actually check the mac against the entry
    # It might be that the rule aged out and we need to re-learn it.
    # We also don't bother to learn non-IP packets (like DHCP), preferring instead to just flood those out the 
    # ports blindly until we hit a real IP.  Then we can learn the mac and IP at the same time.  

    if not self.nib.learned(src) and (eth.ethertype == 0x0800 or eth.ethertype == 0x0806):

      if eth.ethertype == 0x0800:
        p_ip = pkt.get_protocols(ipv4.ipv4)[0]
        src_ip = p_ip.src
      elif eth.ethertype == 0x0806:
        p_arp = pkt.get_protocols(arp.arp)[0]
        src_ip = p_arp.src_ip

      match_mac_src = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_src = src )
      match_mac_dst = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_dst = src )

      # If this is coming from a router, we add goto table 2 rules instead
      target_ip_net = self.nib.actual_net_for(switch)
      if src_ip == NetUtils.ip_for_network(target_ip_net, 1):
        OpenflowUtils.add_goto_table(dp, priority=0, match=match_mac_src, goto_table_id=2, table_id=0)
        OpenflowUtils.add_goto_table(dp, priority=0, match=match_mac_dst, goto_table_id=2, table_id=1)

        self.nib.learn(switch, self.nib.ROUTER_PORT, in_port, src, src_ip)

      else:
        # A new packet carries information on the mac address and port, which we turn into a 
        # GOTO-table 1 rule in table 0
        OpenflowUtils.add_goto_table(dp, priority=65535, match=match_mac_src, goto_table_id=1, table_id=0)

        # And a send-to-port instruction for a destination match in table 1
        actions = [ parser.OFPActionOutput(in_port) ]
        OpenflowUtils.add_flow(dp, priority=0, match=match_mac_dst, actions=actions, table_id=1)

        # Learn it for posterity 
        self.nib.learn(switch, self.nib.ENDHOST_PORT, in_port, src, src_ip)

    # Now we have to deal with the Mac destination.  If we know it already, send the packet out that port.
    # Otherwise flood it.  TODO: We should probably check to make sure the switch is right 
    output_p = self.nib.port_for_mac(dst)
    if output_p == None:
      output_p = ofproto.OFPP_FLOOD

    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
      in_port=in_port, actions=[ parser.OFPActionOutput(output_p) ], data=msg.data)
    dp.send_msg(out)
