# NetworkInformationBase (nib) for Coscin App
# Craig Riecke, CoSciN Programmer/Nalayst January 2016
#
# Some parts of the NIB are familiar, like the learning table.  Some are highly specialized
# for this app.  In particular, we assume and Ithaca "side" and NYC "side", with 
# corresponding switch, controller, and networks on each side.

import json, logging
from net_utils import NetUtils

class NetworkInformationBase():

  # switches are of the form { "ithaca": RYU dp structure, "nyc": RYU dp structure}
  switches = {}

  # Router ports are tallied on the approriate side
  router_port = { "ithaca": None, "nyc": None }

  # Ports are segregated into ROUTER ports and ENDHOST ports
  ROUTER_PORT = 1
  ENDHOST_PORT = 2

  # This will be seeded with network data in .json file
  coscin_config = {} 

  # hosts = { mac1: (sw1, port1, ip1), mac2: (sw2, port2, ip2), ... }
  hosts = {}

  # index of alternate_path being used now
  preferred_path = 0

  # Configuration

  def load_config(self, config_file):
    f = open(config_file, "r")
    self.coscin_config = json.load(f)
    f.close()

  # Overall operations

  def clear(self):
    self.switches = {}
    self.router_port = { "ithaca": None, "nyc": None }
    self.hosts = {}
    self.preferred_path = 0

  # Switches

  def dpid_to_switch(self, dpid):
    for sw in ["ithaca", "nyc"]:
      if dpid == self.coscin_config[sw]["dpid"]:
        return sw
    return "UKNOWN"

  def switch_to_dpid(self, sw):
    if sw in self.coscin_config:
      return self.coscin_config[sw]["dpid"]
    else:
      return 0

  def save_switch(self, dp):
    switch = self.dpid_to_switch(dp.id)
    self.switches[self.dpid_to_switch(dp.id)] = dp
    return switch

  def switch_description(self, dp):
    return self.switch_for_dp(dp)

  def switches_present(self):
    return self.switches.keys()

  def dp_for_switch(self, switch):
    return self.switches[switch]

  def switch_for_dp(self, dp):
    return self.dpid_to_switch(dp.id)

  def opposite_switch(self, switch):
    return "nyc" if (switch=="ithaca") else "ithaca"

  def switch_for_controller_host(self, host):
    for side in ["ithaca", "nyc"]:
      if host in self.coscin_config[side]["controller_hosts"]:
        return side 
    return None

  # Switch attributes

  def actual_net_for(self, switch):
    return self.coscin_config[switch]["network"]

  def vlan_for_switch(self, switch):
    return self.coscin_config[switch]["vlan"]

  def primary_controller_for_switch(self, switch):
    return self.coscin_config[switch]["controller_hosts"][0]

  def zookeeper_for_switch(self, switch):
    return self.coscin_config[switch]["zookeeper"]

  # Switch, Port, Mac, IP Lookup

  def learn(self, switch, port_type, port, mac, src_ip):
    logging.info("Learning: "+mac+"/"+src_ip+" attached to ( "+switch+", "+str(port)+" )")
    self.hosts[mac] = (switch, port, src_ip)
    if port_type == self.ROUTER_PORT:
      self.router_port[switch] = port
    return True

  def unlearn(self, switch, port):
    m = self.mac_for_port(switch, port)
    if m != None:
      del self.hosts[m]

  def learned(self, mac):
    return mac in self.hosts

  def switch_for_mac(self, src_mac):
    return self.hosts[src_mac][0]

  def port_for_mac(self, src_mac):
    if src_mac in self.hosts:
      return self.hosts[src_mac][1]
    else:
      return None

  def learned_ip(self, src_ip):
    for m in self.hosts:
      (_, _, ip) = self.hosts[m]
      if ip == src_ip:
        return True
    return False

  def port_for_ip(self, src_ip):
    for m in self.hosts:
      (_, p, ip) = self.hosts[m]
      if ip == src_ip:
        return p
    return None

  def mac_for_ip(self, src_ip):
    for m in self.hosts:
      (_, _, ip) = self.hosts[m]
      if ip == src_ip:
        return m
    return None

  def mac_for_port(self, switch, port):
    for m in self.hosts:
      (sw, p, _) = self.hosts[m]
      if sw == switch and p == port:
        return m
    return None

  # Router port information

  def router_port_for_switch(self, switch):
    return self.router_port[switch]

  # Coscin path and network information

  def ip_rewriting(self):
    if "ip_rewriting" in self.coscin_config:
      return self.coscin_config["ip_rewriting"]
    else:
      return True

  def alternate_paths(self):
    return self.coscin_config["alternate_paths"]

  def alternate_nets_for_switch(self, switch):
    return [ ap[switch] for ap in self.alternate_paths() ]

  def preferred_net(self, switch):
    return self.alternate_paths()[self.get_preferred_path()][switch]

  def ip_in_coscin_network(self, dst_ip):
    if NetUtils.ip_in_network(dst_ip, self.actual_net_for("ithaca")):
      return True
    if NetUtils.ip_in_network(dst_ip, self.actual_net_for("nyc")):
      return True    
    for ap in self.alternate_paths():
      if NetUtils.ip_in_network(dst_ip, ap["ithaca"]) or NetUtils.ip_in_network(dst_ip, ap["nyc"]):
        return True
    return False    

  def get_preferred_path(self):
    return self.preferred_path

  def set_preferred_path(self, pp):
    self.preferred_path = pp

  # Given an IP in the virtual net, the "opposite" net is the network on the other side of 
  # the router that continues the particular preferred path.  
  def opposite_net_for(self, src_ip):
    for ap in self.alternate_paths():
      for side in [ "ithaca", "nyc" ]:
        opposite_side = self.opposite_switch(side)
        if NetUtils.ip_in_network(src_ip, ap[opposite_side]):
          return ap[side] 
    return None

  def coscin_net_for(self, src_ip):
    for side in [ "ithaca", "nyc" ]:
      if NetUtils.ip_in_network(src_ip, self.actual_net_for(side)):
        return self.actual_net_for(side)
      for ap in self.alternate_paths():
        if NetUtils.ip_in_network(src_ip, ap[side]):
          return ap[side]
    return None

  # Here, we translate real or virtual ip's over another real or virtual net.  Since the
  # number of nets we care about in CoSciN is pretty small, we just loop through all of them
  # until we find a match.  We extract the host, then pop it verbatim into the dest net.  Bada bing.
  def translate_ip(self, src_ip, new_net):
    current_net = self.coscin_net_for(src_ip)
    if current_net == None:
      return None
    src_host = NetUtils.host_of_ip(src_ip, current_net)
    return NetUtils.ip_for_network(new_net, src_host)

