
import kazoo.client
from ryu.ofproto import ofproto_v1_3

ELECTION_PATH = "/multiple_controllers/master"
DEFAULT_TIMEOUT = 10  

class MultipleControllers(object):
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  def __init__(self, logger, host, zhost):
    super(MultipleControllers, self).__init__()
    self.host = host
    self.logger = logger
    self.zk = kazoo.client.KazooClient(hosts = zhost, timeout = DEFAULT_TIMEOUT)
    self.zk.start()

  def role_request(self, dp, role):
    ofp_parser = dp.ofproto_parser
    msg = ofp_parser.OFPRoleRequest(dp, role, 0)
    dp.send_msg(msg)

  def promote_to_primary(self):
    self.logger.info("Promoted to master controller")
    self.role_request(self.dp, ofproto_v1_3.OFPCR_ROLE_MASTER)

  def handle_datapath(self, ev):
    # We always start as a slave.  If we win the election, we bump ourselves up to master 
    self.dp = ev.msg.datapath
    self.role_request(self.dp, ofproto_v1_3.OFPCR_ROLE_SLAVE)
    self.logger.info("Beginning in backup controller state.  If there's a working primary controller, we'll wait here.")

    self.election = self.zk.Election(ELECTION_PATH, self.host)

    # The following will block until this controller wins the election
    self.election.run(self.promote_to_primary)
