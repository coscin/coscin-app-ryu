# coscin_app.py
# Craig Riecke, CoSciN Developer/Analyst, February, 2016

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

import sys, logging, os, socket, time, thread
from ryu import utils
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
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

  # This is the maximum number of seconds between probes from the switch.  On HP switches, it's listed
  # as the Backoff interval
  MAXIMUM_HEARTBEAT_INTERVAL = 20

  def __init__(self, *args, **kwargs):
    super(CoscinApp, self).__init__(*args, **kwargs)

    # The nib is the universal variable containing network configuration and 
    # learned state (so far)
    nib = NetworkInformationBase()
    self.nib = nib

    config_file = os.getenv("COSCIN_CFG_FILE", "coscin_gates_testbed.json")
    nib.load_config(config_file)

    hostname = socket.gethostname()
    on_switch = self.nib.switch_for_controller_host(hostname)
    if on_switch == None:
      self.logger.error("The hostname "+hostname+" is not present in a controller_hosts attribute for the switch in "+config_file)
      sys.exit(1)
    zookeeper_for_switch = self.nib.zookeeper_for_switch(on_switch)
    if zookeeper_for_switch == "":
      self.mc = None
    else:
      self.mc = MultipleControllers(self.logger, hostname, zookeeper_for_switch)
      self.heartbeat_monitor_started = False

    # Register all handlers
    self.l2_learning_switch_handler = L2LearningSwitchHandler(nib, self.logger)
    self.cross_campus_handler = CrossCampusHandler(nib, self.logger)
    self.arp_handler = ArpHandler(nib, self.logger)
    self.path_selection_handler = PathSelectionHandler(nib, self.logger)

  # The heartbeat timer is started on switch startup.  It ensures that a heartbeat occurs every
  # 10 seconds or so by default.  
  def heartbeat_monitor(self, _):
    while True:
      # If we don't currently hold the lock as a master, just sleep until we do.  
      if self.mc.holds_lock():
        secs_ago = time.time() - self.last_heartbeat
        # If it has stopped, then we relinquish the lock in Zookeeper so the backup controller can be promoted
        # At this point, the controller is in limbo as far as Zookeeper is concerned.  When the Switch Up event
        # happens, it will become a backup controller.  Note: we don't actually send a role_request to the switch
        # to demote it because ... well, we can't contact the switch!  The promotion to master of the other 
        # controller will ensure the demotion of this one takes place. 
        if secs_ago > (2.0 * self.MAXIMUM_HEARTBEAT_INTERVAL):
          self.logger.error("Lost connection with the switch.  Demoting to backup controller.")
          self.mc.release_lock()
          self.nib.clear()
      time.sleep(self.MAXIMUM_HEARTBEAT_INTERVAL)

  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def handle_switch_up(self, ev):
    dp = ev.msg.datapath
    ofp_parser = dp.ofproto_parser
    ofp = dp.ofproto
    self.logger.info("Switch "+str(dp.id)+" says hello.")
    switch = self.nib.save_switch(dp)
    self.logger.info("Connected to Switch: "+self.nib.switch_description(dp))

    if self.mc != None:
      # This will block until the controller actually becomes a primary
      self.mc.handle_datapath(ev)

      # Start background thread to monitor switch-to-controller heartbeat
      self.last_heartbeat = time.time()
      if not self.heartbeat_monitor_started:
        thread.start_new_thread( self.heartbeat_monitor, (self, ) )
      self.heartbeat_monitor_started = True

    OpenflowUtils.delete_all_rules(dp)
    OpenflowUtils.send_table_miss_config(dp)

    self.l2_learning_switch_handler.install_fixed_rules(dp)
    self.cross_campus_handler.install_fixed_rules(dp)
    self.arp_handler.install_fixed_rules(dp)
    self.path_selection_handler.install_fixed_rules(dp)

  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def handle_packet_in(self, ev):
    # The HP considers a successful Packet In as a probe, so we reset the heartbeat here as well
    self.last_heartbeat = time.time()

    msg = ev.msg
    self.logger.debug("Packet In")
    self.l2_learning_switch_handler.packet_in(msg)
    self.cross_campus_handler.packet_in(msg)
    self.arp_handler.packet_in(msg)
    self.path_selection_handler.packet_in(msg)

  @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
  def error_msg_handler(self, ev):
    msg = ev.msg
    self.logger.error('OFPErrorMsg received: type=0x%02x code=0x%02x '
      'message=%s',
       msg.type, msg.code, utils.hex_array(msg.data)
     )

  @set_ev_cls(ofp_event.EventOFPEchoRequest, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
  def echo_request_handler(self, ev):
    self.last_heartbeat = time.time()

  @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
  def port_status_handler(self, ev):
    msg = ev.msg

    # Currently only the l2 switch is interested in these events.
    self.l2_learning_switch_handler.port_status(msg)
