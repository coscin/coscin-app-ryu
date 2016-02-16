# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import gevent.event
import zookeeper

from ryu.ofproto import ofproto_v1_3

LOG = logging.getLogger('ryu.app.multiple_controllers')

ZOO_OPEN_ACL_UNSAFE = {"perms": 0x1f, "scheme": "world", "id": "anyone"}
ROOT_PATH = "/multiple_controllers"
MASTER_PATH = ROOT_PATH + "/master"
SLAVE_PATH = ROOT_PATH + "/slave_"
DEFAULT_TIMEOUT = 10  

class MultipleControllers(object):
  OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

  def __init__(self, role, zhost):
    super(MultipleControllers, self).__init__()
    self.role = ofproto_v1_3.OFPCR_ROLE_MASTER if role == 'master' else \
        ofproto_v1_3.OFPCR_ROLE_SLAVE
    self.zhost = zhost
    self.dpset = {}
    self.cnodes = {}
    self.init_zookeeper()

  def role_request(self, dp, role):
    ofp_parser = dp.ofproto_parser
    msg = ofp_parser.OFPRoleRequest(dp, role, 0)
    dp.send_msg(msg)

  def create_znode(self, path, data, acl, mode):
    ret = None
    try:
      ret = zookeeper.create(self.handle, path, data, acl, mode)
    except zookeeper.NodeExistsException:
      LOG.debug("%s already exists", path)

    return ret

  def delete_znode(self, path):
    try:
      zookeeper.delete(self.handle, path)
    except zookeeper.NoNodeException:
      LOG.debug("%s not exists", path)

  def conn_watcher(self, handle, _type, state, path):
    self.async_result.set()

  def controller_watcher(self):
    new_nodes = zookeeper.get_children(self.handle, ROOT_PATH,
                                       self.controller_watcher_cb)
    if 'master' not in new_nodes:
      # fail over
      cid = self.create_znode(MASTER_PATH, '',
                              [ZOO_OPEN_ACL_UNSAFE],
                              zookeeper.EPHEMERAL)
      if cid != None:
        self.role = ofproto_v1_3.OFPCR_ROLE_MASTER
        old_id = self.cid
        old_path = ROOT_PATH + '/' + old_id
        self.cid = cid[len(ROOT_PATH) + 1:]
        self.delete_znode(old_path)
        for dp in self.dpset.values():
          self.role_request(dp, self.role)

    self.cnodes = new_nodes
    print 'nodes:', self.cnodes

  def controller_watcher_cb(self, handle, type, state, path):
    print('controller_watcher_cb handle: %d type: %d state: %s path: %s' %
      (handle, type, state, path))
    self.controller_watcher()

  def init_zookeeper(self):
    self.async_result = gevent.event.AsyncResult()
    self.handle = zookeeper.init(self.zhost, self.conn_watcher)
    try:
      self.async_result.get(timeout=DEFAULT_TIMEOUT)
    except gevent.timeout.Timeout:
      LOG.debug('connect failure')

    self.create_znode(ROOT_PATH, '', [ZOO_OPEN_ACL_UNSAFE], 0)
    if self.role == ofproto_v1_3.OFPCR_ROLE_MASTER:
      self.cid = self.create_znode(MASTER_PATH, '', [ZOO_OPEN_ACL_UNSAFE], zookeeper.EPHEMERAL)
      if self.cid == None:
        LOG.error('master already exists')
    elif self.role == ofproto_v1_3.OFPCR_ROLE_SLAVE:
      self.cid = self.create_znode(SLAVE_PATH, '', [ZOO_OPEN_ACL_UNSAFE], zookeeper.EPHEMERAL | zookeeper.SEQUENCE)

    self.cid = self.cid[len(ROOT_PATH) + 1:]
    gevent.spawn_later(1, self.controller_watcher)

  def handle_datapath(self, ev):
    dp = ev.msg.datapath
    self.dpset[dp.id] = dp
    self.role_request(dp, self.role)