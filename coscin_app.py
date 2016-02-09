import struct
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp
from ryu.lib import addrconv
from ryu import utils
from openflow_utils import OpenflowUtils
from network_information_base import NetworkInformationBase
from l2_learning_switch_handler import L2LearningSwitchHandler

# Stolen from later version of RYU
# def ipv4_to_int(ip):
#   """
#   Converts human readable IPv4 string to int type representation.
#   :param str ip: IPv4 address string w.x.y.z
#   :returns: unsigned int of form w << 24 | x << 16 | y << 8 | z
#   """
#   return struct.unpack("!I", addrconv.ipv4.text_to_bin(ip))[0]

class CoscinApp(app_manager.RyuApp):
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  def __init__(self, *args, **kwargs):
    super(CoscinApp, self).__init__(*args, **kwargs)

    nib = NetworkInformationBase()
    self.nib = nib
    nib.load_config("coscin_gates_testbed.json")

    self.l2_learning_switch_handler = L2LearningSwitchHandler(nib)

    self.logger.info("CoSciN app started")

  # def send_fixed_rules(self):
  #   dp = self.dp
  #   ofproto = dp.ofproto
  #   parser = dp.ofproto_parser
  #   host_port = 2
  #   bastion_port = 65
  #   router_port = 1
  #   if dp.id == 378372418415616:  # Ithaca switch
  #     real_this_side = ipv4_to_int("192.168.56.100")
  #     real_other_side = ipv4_to_int("192.168.57.100")
  #     imag_this_side = ipv4_to_int("192.168.156.100")
  #     imag_other_side = ipv4_to_int("192.168.157.100")
  #     bastion = ipv4_to_int("192.168.56.101")

  #   elif dp.id == 378372418751232:  # NYC Switch
  #     real_this_side = ipv4_to_int("192.168.57.100")
  #     real_other_side = ipv4_to_int("192.168.56.100")
  #     imag_this_side = ipv4_to_int("192.168.157.100")
  #     imag_other_side = ipv4_to_int("192.168.156.100")
  #     bastion = ipv4_to_int("192.168.57.101")

  #   else:
  #     self.logger.error("Ooops connected switch "+dp.id+"is not known")
    
  #   # Bastion->Host Packets
  #   match = parser.OFPMatch(
  #     in_port = bastion_port 
  #     ,eth_type=0x0800 
  #     ,ipv4_src=bastion  
  #     ,ipv4_dst=real_this_side
  #   )
  #   actions = [ parser.OFPActionOutput(host_port) ]
  #   Utils.add_flow(self.dp, 65535, match, actions, 3)
    
  #   # Host->Bastion Packets
  #   match = parser.OFPMatch(
  #     in_port = host_port 
  #     ,eth_type=0x0800 
  #     ,ipv4_src=real_this_side  
  #     ,ipv4_dst=bastion
  #   )
  #   actions = [ parser.OFPActionOutput(bastion_port) ]
  #   self.add_flow(65534, match, actions, 3)    

  #   # Ingress Packet Capture, Cookie 100
  #   match = parser.OFPMatch(
  #     in_port = host_port 
  #     ,eth_type=0x0800 
  #     ,ipv4_src=real_this_side  
  #     ,ipv4_dst=real_other_side
  #   )
  #   actions = [ parser.OFPActionOutput(ofproto.OFPP_CONTROLLER) ]
  #   self.add_flow(65533, match, actions, 3, cookie=100)    

  #   # Egress Packet Capture, Cookie 200
  #   match = parser.OFPMatch(
  #     in_port = router_port 
  #     ,eth_type=0x0800 
  #     ,ipv4_src=imag_other_side  
  #     ,ipv4_dst=imag_this_side
  #   )
  #   actions = [ parser.OFPActionOutput(ofproto.OFPP_CONTROLLER) ]
  #   self.add_flow(65532, match, actions, 3, cookie=200)    

  # def add_outgoing_dynamic_flow(self, msg):
  #   dp = msg.datapath
  #   ofproto = dp.ofproto
  #   parser = dp.ofproto_parser
  #   host_port = 2
  #   bastion_port = 65
  #   router_port = 1
  #   if dp.id == 378372418415616:  # Ithaca switch
  #     real_this_side = ipv4_to_int("192.168.56.100")
  #     real_other_side = ipv4_to_int("192.168.57.100")
  #     imag_this_side = ipv4_to_int("192.168.156.100")
  #     imag_other_side = ipv4_to_int("192.168.157.100")

  #   elif dp.id == 378372418751232:  # NYC Switch
  #     real_this_side = ipv4_to_int("192.168.57.100")
  #     real_other_side = ipv4_to_int("192.168.56.100")
  #     imag_this_side = ipv4_to_int("192.168.157.100")
  #     imag_other_side = ipv4_to_int("192.168.156.100")

  #   else:
  #     self.logger.error("Ooops connected switch "+dp.id+"is not known")

  #   pkt = packet.Packet(msg.data)
  #   eth = pkt.get_protocols(ethernet.ethernet)[0]
  #   ip = pkt.get_protocols(ipv4.ipv4)[0]

  #   if ip.proto != 0x6:
  #     self.logger.error("Non TCP packet ignored for now")
  #     return

  #   tcp_pkt = pkt.get_protocols(tcp.tcp)[0]

  #   match = parser.OFPMatch(
  #     ipv4_src=ip.src
  #     ,ipv4_dst=ip.dst
  #     ,eth_type=0x0800
  #     ,ip_proto=ip.proto  
  #     ,tcp_src=tcp_pkt.src_port
  #     ,tcp_dst=tcp_pkt.dst_port
  #     ,vlan_vid=1
  #   )
  #   actions = [
  #     parser.OFPActionSetField(ipv4_src=imag_this_side),
  #     parser.OFPActionSetField(ipv4_dst=imag_other_side),
  #     parser.OFPActionOutput(router_port)
  #   ]
  #   self.add_flow(0, match, actions, 2, idle_timeout=60)
  #   self.logger.error("Added outgoing hash rule for "+str(ip.src)+" -> "+str(ip.dst))
  #   # TODO: Maybe also send the packet out

  # def add_incoming_dynamic_flow(self, msg):
  #   dp = msg.datapath
  #   ofproto = dp.ofproto
  #   parser = dp.ofproto_parser
  #   host_port = 2
  #   bastion_port = 65
  #   router_port = 1
  #   if dp.id == 378372418415616:  # Ithaca switch
  #     real_this_side = ipv4_to_int("192.168.56.100")
  #     real_other_side = ipv4_to_int("192.168.57.100")
  #     imag_this_side = ipv4_to_int("192.168.156.100")
  #     imag_other_side = ipv4_to_int("192.168.157.100")

  #   elif dp.id == 378372418751232:  # NYC Switch
  #     real_this_side = ipv4_to_int("192.168.57.100")
  #     real_other_side = ipv4_to_int("192.168.56.100")
  #     imag_this_side = ipv4_to_int("192.168.157.100")
  #     imag_other_side = ipv4_to_int("192.168.156.100")

  #   else:
  #     self.logger.error("Ooops connected switch "+dp.id+"is not known")

  #   pkt = packet.Packet(msg.data)
  #   eth = pkt.get_protocols(ethernet.ethernet)[0]
  #   ip = pkt.get_protocols(ipv4.ipv4)[0]

  #   if ip.proto != 0x6:
  #     self.logger.error("Non TCP packet ignored for now")
  #     return

  #   tcp_pkt = pkt.get_protocols(tcp.tcp)[0]

  #   match = parser.OFPMatch(
  #     ipv4_src=ip.src
  #     ,ipv4_dst=ip.dst
  #     ,eth_type=0x0800
  #     ,ip_proto=ip.proto  
  #     ,tcp_src=tcp_pkt.src_port
  #     ,tcp_dst=tcp_pkt.dst_port
  #     ,vlan_vid=1
  #   )
  #   actions = [
  #     parser.OFPActionSetField(ipv4_src=real_other_side),
  #     parser.OFPActionSetField(ipv4_dst=real_this_side),
  #     parser.OFPActionOutput(host_port)
  #   ]
  #   self.add_flow(0, match, actions, 2, idle_timeout=60)
  #   self.logger.error("Added incoming hash rule for "+str(ip.src)+" -> "+str(ip.dst))


  @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
  def handle_switch_bringup(self, ev):

    dp = ev.msg.datapath
    self.nib.save_switch(dp)
    self.logger.info("Connected to Frenetic - Switch: "+self.nib.switch_description())

    OpenflowUtils.delete_all_rules(dp)
    OpenflowUtils.send_table_miss_config(dp)

    self.l2_learning_switch_handler.install_fixed_rules()

  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def _packet_in_handler(self, ev):
    msg = ev.msg
    # cookie = msg.cookie
    # if cookie == 100:
    #   self.add_outgoing_dynamic_flow(msg)
    # elif cookie == 200:
    #   self.add_incoming_dynamic_flow(msg)
    # else:
    #   self.logger.error("Received packet with unrecognized cookie value")
    self.l2_learning_switch_handler.packet_in(msg)

  @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
  def error_msg_handler(self, ev):
    msg = ev.msg
    self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
      'message=%s',
       msg.type, msg.code, utils.hex_array(msg.data)
     )
