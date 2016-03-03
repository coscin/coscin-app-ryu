# l2_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, March, 2016

# A RYU app that acts exactly like an L2 switch, heavily optimized for HP's 
# v3 module Custom Pipeline default implentation, but using only tables 0 and 1

#   +-Table 0-+  +-Table 1-+  +-Table 2-+   +-Table 3-+
#   + VLAN    +  + VLAN    +  + IP_SRC  +   + "Any"   +
#   + ETH_SRC +  + ETH_DST +  + IP_DST  +   +         +  
#   +         +  +         +  + PROTO   +   +         +  
#   +         +  +         +  + SRC_PORT+   +         +  
#   +         +  +         +  + DST_PORT+   +         +  
#   +---------+  +---------+  +---------+   +---------+

import logging, os, socket, time, thread
from ryu import utils
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet
from ryu.ofproto import ofproto_v1_3
from openflow_utils import OpenflowUtils
from network_information_base import NetworkInformationBase
from multiple_controllers import MultipleControllers

class L2SwitchApp(app_manager.RyuApp):
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  # This is the maximum number of seconds between probes from the switch.  On HP switches, it's listed
  # as the Backoff interval
  MAXIMUM_HEARTBEAT_INTERVAL = 20

  LEARN_NEW_MACS_RULE = 1000
  LEARNED_MAC_TIMEOUT = 3600  # = 1 Hour

  def __init__(self, *args, **kwargs):
    super(L2SwitchApp, self).__init__(*args, **kwargs)

    # The nib is the universal variable containing network configuration and 
    # learned state (so far)
    nib = NetworkInformationBase()
    self.nib = nib

    nib.load_config(os.getenv("COSCIN_CFG_FILE", "coscin_gates_testbed.json"))

    hostname = socket.gethostname()
    on_switch = self.nib.switch_for_controller_host(hostname)
    zookeeper_for_switch = self.nib.zookeeper_for_switch(on_switch)
    self.mc = MultipleControllers(self.logger, hostname, zookeeper_for_switch)
    self.heartbeat_monitor_started = False

  # The heartbeat timer is started on switch startup.  It ensures that a heartbeat occurs every
  # 10 seconds or so by default.  
  def heartbeat_monitor(self, _):
    while True:
      # If we don't currently hold the lock as a master, just sleep until we do.  
      if self.mc.holds_lock():
        secs_ago = time.time() - self.last_heartbeat
        if secs_ago > (2.0 * self.MAXIMUM_HEARTBEAT_INTERVAL):
          self.logger.error("Lost connection with the switch.  Demoting to backup controller.")
          self.mc.release_lock()
          self.nib.clear()
      time.sleep(self.MAXIMUM_HEARTBEAT_INTERVAL)

  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def handle_switch_up(self, ev):
    dp = ev.msg.datapath
    parser = dp.ofproto_parser
    ofproto = dp.ofproto
    switch = self.nib.save_switch(dp)
    self.logger.info("Connected to Switch: "+self.nib.switch_description(dp))

    # This will block until the controller actually becomes a primary
    self.mc.handle_datapath(ev)

    # Start background thread to monitor switch-to-controller heartbeat
    self.last_heartbeat = time.time()
    if not self.heartbeat_monitor_started:
      thread.start_new_thread( self.heartbeat_monitor, (self, ) )
    self.heartbeat_monitor_started = True

    OpenflowUtils.delete_all_rules(dp)
    OpenflowUtils.send_table_miss_config(dp)

    # Table 0, the Source Mac table, has table miss=Goto Controller so it can learn 
    # newly-connected macs
    match_all = parser.OFPMatch()
    actions = [ parser.OFPActionOutput(ofproto.OFPP_CONTROLLER) ]
    OpenflowUtils.add_flow(dp, priority=0, match=match_all, actions=actions, table_id=0, cookie=self.LEARN_NEW_MACS_RULE)

    # Table 1, the Dest Mac table, has table-miss = Flood.  If the destination exists,
    # it'll send a reply packet that'll get learned in table 0.  We can afford to do a 
    # sloppy non-spanning-tree flood because there's only one switch in our topology
    actions = [ parser.OFPActionOutput(ofproto.OFPP_FLOOD) ]
    OpenflowUtils.add_flow(dp, priority=0, match=match_all, actions=actions, table_id=1)


  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def handle_packet_in(self, ev):
    # The HP considers a successful Packet In as a probe, so we reset the heartbeat here as well
    self.last_heartbeat = time.time()

    msg = ev.msg
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

    if not self.nib.learned(src):
      match_mac_src = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_src = src )
      match_mac_dst = parser.OFPMatch( vlan_vid = self.nib.vlan_for_switch(switch), eth_dst = src )

      OpenflowUtils.add_goto_table(dp, priority=65535, match=match_mac_src, goto_table_id=1, table_id=0)

      # And a send-to-port instruction for a destination match in table 1
      actions = [ parser.OFPActionOutput(in_port) ]
      OpenflowUtils.add_flow(dp, priority=0, match=match_mac_dst, actions=actions, table_id=1)

      # Learn it for posterity 
      self.nib.learn(switch, self.nib.ENDHOST_PORT, in_port, src, "0.0.0.0")

    # Now we have to deal with the Mac destination.  If we know it already, send the packet out that port.
    # Otherwise flood it.   
    output_p = self.nib.port_for_mac(dst)
    if output_p == None:
      output_p = ofproto.OFPP_FLOOD

    out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
      in_port=in_port, actions=[ parser.OFPActionOutput(output_p) ], data=msg.data)
    dp.send_msg(out)

  @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
  def error_msg_handler(self, ev):
    msg = ev.msg
    self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
      'message=%s',
       msg.type, msg.code, utils.hex_array(msg.data)
     )

  @set_ev_cls(ofp_event.EventOFPEchoRequest, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
  def echo_request_handler(self, ev):
    self.last_heartbeat = time.time()
