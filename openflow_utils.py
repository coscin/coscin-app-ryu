# Universal utilities for Coscin App

import logging
from ryu.lib.packet import packet, ethernet, arp
from ryu.ofproto import ether

class OpenflowUtils():

  # Used as destination Mac for ARP replies that we ignore
  BOGUS_MAC = "00:de:ad:00:be:ef"

  @staticmethod
  def add_flow_with_instructions(dp, priority, match, inst, table_id, idle_timeout, cookie):
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    mod = parser.OFPFlowMod(datapath=dp, priority=priority,
      cookie=cookie, command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout, hard_timeout=0,
      flags=ofproto.OFPFF_SEND_FLOW_REM, match=match, instructions=inst, table_id=table_id)
    dp.send_msg(mod)

  @staticmethod
  def add_flow(dp, priority, match, actions, table_id, idle_timeout=0, cookie=0):
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    OpenflowUtils.add_flow_with_instructions(dp, priority, match, inst, table_id, idle_timeout, cookie)

  @staticmethod
  def add_goto_table(dp, priority, match, goto_table_id, table_id, idle_timeout=0, cookie=0):
    parser = dp.ofproto_parser
    inst = [ parser.OFPInstructionGotoTable(goto_table_id) ]
    OpenflowUtils.add_flow_with_instructions(dp, priority, match, inst, table_id, idle_timeout, cookie)

  @staticmethod
  def delete_rules_from_table(dp, tid):
    parser = dp.ofproto_parser
    ofp = dp.ofproto
    match = parser.OFPMatch()
    m = parser.OFPFlowMod(dp, 0, 0,
      tid,
      ofp.OFPFC_DELETE,
      0, 0, 1, 
      ofp.OFPCML_NO_BUFFER, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, match, instructions=[])
    dp.send_msg(m)

  @staticmethod
  def delete_all_rules(dp):
    OpenflowUtils.delete_rules_from_table(dp, 0)
    OpenflowUtils.delete_rules_from_table(dp, 1)
    OpenflowUtils.delete_rules_from_table(dp, 2)
    OpenflowUtils.delete_rules_from_table(dp, 3)

  @staticmethod
  def config_table_miss_from(dp, fr, to):
    parser = dp.ofproto_parser
    match = parser.OFPMatch()
    OpenflowUtils.add_goto_table(dp, priority=0, match=match, goto_table_id=to, table_id=fr)

  @staticmethod
  def send_table_miss_config(dp):
    OpenflowUtils.config_table_miss_from(dp, 2, 3)

  @staticmethod
  def send_arp_request(dp, src_ip, target_ip):
    parser = dp.ofproto_parser
    ofproto = dp.ofproto

    # It's unclear what the source should be, since the switch has no mac or IP address.
    # It just hears all replies and picks out the interesting stuff.
    src_mac = OpenflowUtils.BOGUS_MAC
    dst_mac = "ff:ff:ff:ff:ff:ff"
    e = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether.ETH_TYPE_ARP)
    pkt = arp.arp_ip(arp.ARP_REQUEST, src_mac, src_ip, "00:00:00:00:00:00", target_ip)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(pkt)
    p.serialize()
    logging.info("Sending Arp Request to "+target_ip)          

    out = parser.OFPPacketOut(datapath=dp, in_port=2, buffer_id = ofproto.OFP_NO_BUFFER, 
      actions=[ parser.OFPActionOutput(ofproto.OFPP_ALL) ], 
      data = p.data
    )
    dp.send_msg(out)