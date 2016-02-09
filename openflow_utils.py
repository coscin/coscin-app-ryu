# Universal utilities for Coscin App

class OpenflowUtils():

  @staticmethod
  def add_flow(dp, priority, match, actions, table_id, idle_timeout=0, cookie=0):
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    mod = parser.OFPFlowMod(datapath=dp, priority=priority,
      cookie=cookie, command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout, hard_timeout=0,
      flags=ofproto.OFPFF_SEND_FLOW_REM, match=match, instructions=inst, table_id=table_id)
    dp.send_msg(mod)

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
    ofproto = dp.ofproto
    parser = dp.ofproto_parser
    # This is like add_flow, but the instruction is different
    match = parser.OFPMatch()
    inst = [ parser.OFPInstructionGotoTable(to) ]
    mod = parser.OFPFlowMod(datapath=dp, priority=0,
      cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
      flags=ofproto.OFPFF_SEND_FLOW_REM, match=match, instructions=inst, table_id=fr)
    dp.send_msg(mod)

  @staticmethod
  def send_table_miss_config(dp):
    OpenflowUtils.config_table_miss_from(dp, 2,3)


