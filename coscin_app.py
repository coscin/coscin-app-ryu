# coscin_switch_app.py
# Craig Riecke, CoSciN Developer/Analyst, December, 2015

# A RYU app that acts mostly like an L2 switch, but also does rudimentary routing to
# one of three physical networks based on utilization statistics.  This implementation
# is heavily optimized for HP's v3 module Custom Pipeline default implentation:

#   +-Table 0-+  +-Table 1-+  +-Table 2-+   +-Table 3-+
#   + VLAN    +  + VLAN    +  + IP_SRC  +   + "Any"   +
#   + ETH_SRC +  + ETH_DST +  + IP_DST  +   +         +  
#   +         +  +         +  + PROTO   +   +         +  
#   +         +  +         +  + SRC_PORT+   +         +  
#   +         +  +         +  + DST_PORT+   +         +  
#   +---------+  +---------+  +---------+   +---------+

import logging, os, socket
from ryu import utils
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from openflow_utils import OpenflowUtils
from network_information_base import NetworkInformationBase
from l2_learning_switch_handler import L2LearningSwitchHandler
from cross_campus_handler import CrossCampusHandler
from arp_handler import ArpHandler
from path_selection_handler import PathSelectionHandler
from multiple_controllers import MultipleControllers

class CoscinApp(app_manager.RyuApp):
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  def __init__(self, *args, **kwargs):
    super(CoscinApp, self).__init__(*args, **kwargs)

    # The nib is the universal variable containing network configuration and 
    # learned state (so far)
    nib = NetworkInformationBase()
    self.nib = nib

    nib.load_config(os.getenv("COSCIN_CFG_FILE", "coscin_gates_testbed.json"))

    hostname = socket.gethostname()
    on_switch = self.nib.switch_for_controller_host(hostname)
    primary_controller_host = self.nib.primary_controller_for_switch(on_switch)
    zookeeper_for_switch = self.nib.zookeeper_for_switch(on_switch)
    role = "master" if hostname == primary_controller_host else "slave"
    self.mc = MultipleControllers(role, zookeeper_for_switch)

    # Register all handlers
    self.l2_learning_switch_handler = L2LearningSwitchHandler(nib, self.logger)
    self.cross_campus_handler = CrossCampusHandler(nib, self.logger)
    self.arp_handler = ArpHandler(nib, self.logger)
    self.path_selection_handler = PathSelectionHandler(nib, self.logger)

  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def handle_switch_up(self, ev):
    dp = ev.msg.datapath
    ofp_parser = dp.ofproto_parser
    ofp = dp.ofproto
    switch = self.nib.save_switch(dp)
    self.logger.info("Connected to Switch: "+self.nib.switch_description(dp))

    self.mc.handle_datapath(ev)

  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def handle_packet_in(self, ev):
    msg = ev.msg
    self.l2_learning_switch_handler.packet_in(msg)
    self.cross_campus_handler.packet_in(msg)
    self.arp_handler.packet_in(msg)
    self.path_selection_handler.packet_in(msg)

  @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
  def error_msg_handler(self, ev):
    msg = ev.msg
    self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
      'message=%s',
       msg.type, msg.code, utils.hex_array(msg.data)
     )
