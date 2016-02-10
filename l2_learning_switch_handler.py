from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp
from openflow_utils import OpenflowUtils

class L2LearningSwitchHandler():

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
      # TODO: 1000 is magic number
      OpenflowUtils.add_flow(dp, priority=0, match=match_all, actions=actions, table_id=0, cookie=1000)

      # Table 1, the Dest Mac table, has table-miss = Flood.  If the destination exists,
      # it'll send a reply packet that'll get learned in table 0.  We can afford to do a 
      # sloppy non-spanning-tree flood because there's only one switch in our topology
      actions = [ parser.OFPActionOutput(ofproto.OFPP_FLOOD) ]
      OpenflowUtils.add_flow(dp, priority=0, match=match_all, actions=actions, table_id=1)

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
    # It might be that the rule aged out and we need to re-learn it
    if not self.nib.learned(src):

      # A new packet carries information on the mac address and port, which we turn into a 
      # GOTO-table 1 rule in table 0
      # TODO: packets going to/from a router need to hop over to table 2, so install a Goto table 2 for that instead. 
      match_mac = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_src = src )
      inst = [ parser.OFPInstructionGotoTable(1) ]
      mod = parser.OFPFlowMod(datapath=dp, priority=65535,
        cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        flags=ofproto.OFPFF_SEND_FLOW_REM, match=match_mac, instructions=inst, table_id=0)
      dp.send_msg(mod)

      # And a send-to-port instruction for a destination match in table 1
      # TODO: packets going to/from a router need to hop over to table 2, so install a Goto table 2 for that instead. 
      match_mac = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_dst = src )
      actions = [ parser.OFPActionOutput(in_port) ]
      OpenflowUtils.add_flow(dp, priority=0, match=match_mac, actions=actions, table_id=1)

      # Learn it for posterity 
      self.nib.learn(switch, self.nib.ENDHOST_PORT, in_port, src)

    # Now we have to deal with the Mac destination.  If we know it already, send the packet out that port.
    # Otherwise flood it.  TODO: We should probably check to make sure the switch is right 
    output_p = self.nib.port_for_mac(dst)
    if output_p == None:
      output_p = ofproto.OFPP_FLOOD

    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
      in_port=in_port, actions=[parser.OFPActionOutput(output_p)], data=msg.data)
    dp.send_msg(out)
