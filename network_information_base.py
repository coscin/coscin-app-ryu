# NetworkInformationBase (nib) for Coscin App
# Craig Riecke, CoSciN Programmer/Nalayst January 2016
#
# Some parts of the NIB are familiar, like the ARP cache.  Some are highly specialized
# for this app.  In particular, we assume and Ithaca "side" and NYC "side", with 
# corresponding switch, controller, and networks on each side.

import json, logging
from net_utils import NetUtils

class NetworkInformationBase():

  # switches are of the form { "ithaca": RYU dp structure, "nyc": RYU dp structure}
  switches = {}

  # Ports are segregated into ROUTER ports and ENDHOST ports
  ROUTER_PORT = 1
  ENDHOST_PORT = 2

  # This will be seeded with network data in .json file
  coscin_config = {} 

  # hosts = { mac1: (sw1, port1), mac2: (sw2, port2), ... }
  hosts = {}

  # index of alternate_path being used now
  preferred_path = 0

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

  def load_config(self, config_file):
    f = open(config_file, "r")
    self.coscin_config = json.load(f)
    f.close()

  def actual_net_for(self, switch):
    return self.coscin_config[switch]["network"]

  def save_switch(self, dp):
    self.switches[self.dpid_to_switch(dp.id)] = dp

  def dp(self):
    return self.dp

  def switch_description(self):
    # TODO: Handle more than one switch
    return self.switches.keys()[0] 

  # TODO: Make this configurable
  def vlan_for_switch(self, switch):
    return 1

  # Update NIB tables and return True if table changes occurred.  Return False otherwise.
  def learn(self, switch, port_type, port, mac, src_ip= "None"):
    #if self.learned(switch, port):
    #  return False

    logging.info("Learning: "+mac+"/"+src_ip+" attached to ( "+switch+", "+str(port)+" )")
    self.hosts[mac] = (switch, port)
    #self.arp_cache[src_ip] = (switch, port, mac)
    #self.unlearned_ports[switch].remove(port)
    #if port_type == self.ENDHOST_PORT:
      #host_portion = NetUtils.host_of_ip(src_ip, self.coscin_config[switch]["network"])
      #self.endhosts[switch].append( (host_portion, port, mac, src_ip) )
      # We also add entries for this host on all its imaginary paths
      #for ap in self.coscin_config["alternate_paths"]:
        #virtual_ip = NetUtils.ip_for_network(ap[switch], host_portion)
        #self.arp_cache[virtual_ip] = (switch, port, mac)
    #elif port_type == self.ROUTER_PORT:
      #self.router_port[switch] = port
    #else:
      #logging.error("Unknown port type: "+str(port_type))
      #return False
    return True

  def learned(self, mac):
    return mac in self.hosts

  def switch_for_mac(self, src_mac):
    return self.hosts[src_mac][0]

  def port_for_mac(self, src_mac):
    if src_mac in self.hosts:
      return self.hosts[src_mac][1]
    else:
      return None
      
  def switches_present(self):
    return self.switches.keys()

  def dp_for_switch(self, switch):
    return self.switches[switch]

  def switch_for_dp(self, dp):
    return self.dpid_to_switch(dp.id)

  def router_mac_for_switch(self, switch):
    # TODO: Pass this back from the NIB after learning it.  In the case of the testbed Cisco router, this is 
    # the same on either side.
    return "00:0a:f3:50:96:80"

  def router_port_for_switch(self, switch):
    # TODO: Pass back from NIB after learning it.
    return 1

  def alternate_paths(self):
    return self.coscin_config["alternate_paths"]

  def preferred_net(self, switch):
    return self.alternate_paths()[self.get_preferred_path()][switch]

  def opposite_switch(self, switch):
    return "nyc" if (switch=="ithaca") else "ithaca"

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

  def translate_alternate_net(self, dst_ip):
    # First find out which side (ithaca or nyc) it's on
    found_side = None
    for ap in self.alternate_paths():
      for side in ["ithaca", "nyc"]:
        if NetUtils.ip_in_network(dst_ip, ap[side]):
          found_side = side
          imaginary_net = ap[side]

    if side == None:
      logging.error("Ooops.  Got an ARP request for a net we don't know about.  Oh well.")
      return False
    else:
      host = NetUtils.host_of_ip(dst_ip, imaginary_net)
      return NetUtils.ip_for_network(self.actual_net_for(found_side), host)
