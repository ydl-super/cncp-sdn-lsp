#!/usr/bin/python

from netconf import server, util, nsmap_add
from optparse import OptionParser
from pyroute2 import IPRoute

try:
    from lxml import etree
except ImportError:
    from xml.etree import ElementTree as etree

import logging
import time
import json

# Global variables definition

# Server reference
netconf_server = None
# Netlink socket
ip_route = None
# Cache of the resolved interfaces
interfaces = ['ens192']
idxs = {}
# logger reference
logger = logging.getLogger(__name__)
# Server port, user and password
NC_PORT = 830
NC_USER = 'my'
NC_PASSWORD = '123456'
# Debug option
SERVER_DEBUG = False
# Namespace mapping
NS = {
  "nc":"urn:ietf:params:xml:ns:netconf:base:1.0",
  "srv6":"urn:ietf:params:xml:ns:yang:srv6-explicit-path"
}
# SRv6 mapping
OP = {
  "create":"add",
  "remove":"del",
  "destination":"dst",
  "device":"dev",
  "action":"action",
  "nexthop":"nexthop",
  "table":"table",
  "vrftable":"vrftable",
  "segments":"segs"
}

# Yang utilities class
class YangUtils:
  """ Class containing utilities method for Yang processing """

  @staticmethod
  def remove_urn(text):
    return text[text.find('}') + 1:]

  """
  SRv6 explicit path configuration example

  <srv6-explicit-path operation="create" xmlns="urn:ietf:params:xml:ns:yang:srv6-explicit-path">
    <path>
        <destination>2222:4::2/128</destination>
        <sr-path>
            <srv6-segment>2222:3::2</srv6-segment>
        </sr-path>
        <encapmode>inline</encapmode>
        <device>eth0</device>
    </path>
  </srv6-explicit-path>
  """

  @staticmethod
  def get_srv6_loc(netconf_localsid):
    # Init steps
    localsid = {}
    # Get srv6 path
    for elem in netconf_localsid:
      tag = YangUtils.remove_urn(elem.tag)
      # Get destination
      if tag == "destination":
        localsid[OP[tag]] = elem.text
      # Get action
      if tag == "action":
        localsid[OP["action"]] = elem.text
      # Get nexthop
      if tag == "nexthop":
        localsid[OP[tag]] = elem.text
      # Get nexthop
      if tag == "table":
        localsid[OP[tag]] = elem.text
      # Get nexthop
      if tag == "vrftable":
        localsid[OP[tag]] = elem.text
      # Get segments
      if tag == "sr-path":
        segments = []
        for subelm in elem:
          # Get segments
          if YangUtils.remove_urn(subelm.tag) == "srv6-segment":
              segments.append(subelm.text)
        localsid[OP["segments"]] = segments
      # Get destination
      if tag == "device":
        localsid[OP[tag]] = elem.text
    return localsid

  @staticmethod
  def get_srv6_ls_op(netconf_data):
    # Get operation from srv6-explicit-path
    for attrib in netconf_data.attrib:
      if YangUtils.remove_urn(attrib) == "operation":
          return netconf_data.attrib[attrib]
    # Not found
    raise Exception("No operation found in netconf data")

  @staticmethod
  def is_srv6_loc(rpc):
    #Locate object
    netconf_data = rpc.find("edit-config/nc:config/srv6:srv6-localsid/", NS)
    logger.info(netconf_data)
    return netconf_data is not None

  @staticmethod
  def get_srv6_ls(rpc):
    # Init steps
    msg = {}
    netconf_data = rpc.find("edit-config/nc:config/", NS)
    logger.info(netconf_data)
    # Get operation type
    op_type = OP[YangUtils.get_srv6_ls_op(netconf_data)]
    # Let's parse paths
    localsids = []
    netconf_localsids = list(netconf_data)
    for netconf_localsid in netconf_localsids:
      localsids.append(YangUtils.get_srv6_loc(netconf_localsid))
    # Finally let's fill the python dict
    msg['operation'] = op_type
    msg['localsids'] = localsids
    return msg

# Netconf methods definition
class SRv6NetconfMethods(server.NetconfMethods):
  """ Class containing the methods that will be called upon reception of SRv6 Netconf external calls"""

  def nc_append_capabilities(self, capabilities_answered):

    capability_list = ["urn:ietf:params:xml:ns:yang:srv6-localsid"]

    for cap in capability_list:
      elem = etree.Element("capability")
      elem.text = cap
      capabilities_answered.append(elem)
    return

  def rpc_edit_config(self, unused_session, rpc, *unused_params):
        logger.debug("rpc_edit_config")
        logger.debug("RPC received:%s", format(etree.tostring(rpc, pretty_print=True)))
        # srv6-explicit-path Yang model
        if YangUtils.is_srv6_loc(rpc):
          srv6_config = YangUtils.get_srv6_ls(rpc)
          logger.debug("config received:\n%s", json.dumps(srv6_config, indent=2, sort_keys=True))
          # Let's push the routes
          for localsid in srv6_config["localsids"]:
            if localsid['action'] == "End.DX4":
              ip_route.route(srv6_config["operation"], dst=localsid['dst'], oif=idxs[localsid['dev']],
                encap={'type':'seg6local', 'action':localsid['action'], 'nh4':localsid['nexthop']})
            if localsid['action'] == "End.DX6":
              ip_route.route(srv6_config["operation"], dst=localsid['dst'], oif=idxs[localsid['dev']],
                encap={'type':'seg6local', 'action':localsid['action'], 'nh6':localsid['nexthop']})
            if localsid['action'] == "End.DT4" or localsid['action'] == "End.DT46":
              ip_route.route(srv6_config["operation"], dst=localsid['dst'], oif=idxs[localsid['dev']],
                encap={'type':'seg6local', 'action':localsid['action'], 'vrf_table':localsid['vrftable']})
            if localsid['action'] == "End.DT6":
              if localsid['table'] != None:
                ip_route.route(srv6_config["operation"], dst=localsid['dst'], oif=idxs[localsid['dev']],
                  encap={'type':'seg6local', 'action':localsid['action'], 'table':localsid['table']})
              if localsid['vrftable'] != None:
                ip_route.route(srv6_config["operation"], dst=localsid['dst'], oif=idxs[localsid['dev']],
                  encap={'type':'seg6local', 'action':localsid['action'], 'vrf_table':localsid['vrftable']})
            if localsid['action'] == "End.B6" or localsid['action'] == "End.B6.Encap":
              ip_route.route(srv6_config["operation"], dst=localsid['dst'], oif=idxs[localsid['dev']],
                encap={'type':'seg6local', 'action':localsid['action']},srh={'segs':localsid['segs']})
          return etree.Element("ok")
        logger.info("not supported yet")
        return etree.Element("not-supported")
# Start Netconf server
def start_server():
  # Configure Netconf server listener and ip route
  global netconf_server, ip_route
  # Setup Netconf
  if netconf_server is not None:
    logger.error("Netconf Server is already up and running")
  else:
    server_ctl = server.SSHUserPassController(username=NC_USER,
                          password=NC_PASSWORD)
    netconf_server = server.NetconfSSHServer(server_ctl=server_ctl,
                         server_methods=SRv6NetconfMethods(),
                         port=NC_PORT,
                         debug=SERVER_DEBUG)
  # Setup ip route
  if ip_route is not None:
    logger.error("IP Route is already setup")
  else:
    ip_route = IPRoute()
  # Resolve the interfaces
  for interface in interfaces:
    idxs[interface] = ip_route.link_lookup(ifname=interface)[0]
  # Start the loop for Netconf
  logger.info("Listening Netconf")
  while True:
    time.sleep(5)

# Parse options
def parse_options():
  parser = OptionParser()
  parser.add_option("-d", "--debug", action="store_true", help="Activate debug logs")
  # Parse input parameters
  (options, args) = parser.parse_args()
  # Setup properly the logger
  if options.debug:
    logging.basicConfig(level=logging.DEBUG)
  else:
    logging.basicConfig(level=logging.INFO)
  SERVER_DEBUG = logger.getEffectiveLevel() == logging.DEBUG
  logger.info("SERVER_DEBUG:" + str(SERVER_DEBUG))

if __name__ == "__main__":
  parse_options()
  start_server()
