
import kazoo.client
from ryu.ofproto import ofproto_v1_3

LOCK_PATH = "/multiple_controllers/master"
DEFAULT_TIMEOUT = 10  

def my_listener(state):
  if state == KazooState.LOST:
    self.logger.info("Zookeeper session lost")
  elif state == KazooState.SUSPENDED:
    self.logger.info("Zookeeper session suspended")
  else:
    self.logger.info("Zookeeper session connected/reconnected")

class MultipleControllers(object):
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  def __init__(self, logger, host, zhost):
    super(MultipleControllers, self).__init__()
    self.host = host
    self.logger = logger
    self.zk = kazoo.client.KazooClient(hosts = zhost, timeout = DEFAULT_TIMEOUT)
    self.zk.start()
    self.zk.add_listener(my_listener)
    self.lock = None

  def role_request(self, dp, role):
    ofp_parser = dp.ofproto_parser
    msg = ofp_parser.OFPRoleRequest(dp, role, 0)
    dp.send_msg(msg)

  def handle_datapath(self, ev):
    # We always start as a slave.  If we win the election, we bump ourselves up to master 
    self.dp = ev.msg.datapath
    self.role_request(self.dp, ofproto_v1_3.OFPCR_ROLE_SLAVE)
    self.logger.info("Beginning in backup controller state.  If there's a working primary controller, we'll wait here.")

    self.lock = self.zk.Lock(LOCK_PATH, self.host)

    # The following will block until this controller wins the lock
    self.lock.acquire()

    self.logger.info("Promoted to master controller")
    self.role_request(self.dp, ofproto_v1_3.OFPCR_ROLE_MASTER)

  def release_lock(self):
    self.lock.release()
    self.lock = None

  def holds_lock(self):
    return self.lock != None