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

class CoscinApp(app_manager.RyuApp):
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  def __init__(self, *args, **kwargs):
    super(CoscinApp, self).__init__(*args, **kwargs)

    nib = NetworkInformationBase()
    self.nib = nib
    nib.load_config("coscin_gates_testbed.json")

    self.l2_learning_switch_handler = L2LearningSwitchHandler(nib)
    self.cross_campus_handler = CrossCampusHandler(nib, self.logger)
    self.arp_handler = ArpHandler(nib, self.logger)

  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def handle_switch_bringup(self, ev):
    dp = ev.msg.datapath
    self.nib.save_switch(dp)
    self.logger.info("Connected to Switch: "+self.nib.switch_description())

    OpenflowUtils.delete_all_rules(dp)
    OpenflowUtils.send_table_miss_config(dp)

    self.l2_learning_switch_handler.install_fixed_rules()
    self.cross_campus_handler.install_fixed_rules()
    self.arp_handler.install_fixed_rules()

  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def _packet_in_handler(self, ev):
    msg = ev.msg
    self.l2_learning_switch_handler.packet_in(msg)
    self.cross_campus_handler.packet_in(msg)
    self.arp_handler.packet_in(msg)

  @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
  def error_msg_handler(self, ev):
    msg = ev.msg
    self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
      'message=%s',
       msg.type, msg.code, utils.hex_array(msg.data)
     )
