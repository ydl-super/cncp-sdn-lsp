#!/usr/bin/python

import time

from netconf.client import NetconfSSHSession

try:
    from lxml import etree
except ImportError:
    from xml.etree import ElementTree as etree

# Utility to close Netconf sessions
def close_netconf_session(session):
  # Let's take the reference of the transport
  transport = session.pkt_stream.stream
  # Let's close the Netconf session
  session.close()
  # This is a workaround for RST_ACK
  time.sleep(0.05)
  # Close the transport
  transport.close()
  # Flush the cache
  transport.cache.flush()

# Let's create a NetConf session
session = NetconfSSHSession("10.89.1.160", 830, "my", "123456")

# From the hello, we got the capabilities
for capability in session.capabilities:
  print(capability)

config = """
<edit-config>
<target>
  <running/>
</target>
<default-operation>none</default-operation>
<test-option>test-then-set</test-option>
<error-option>rollback-on-error</error-option>
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <srv6-localsid operation="create" xmlns="urn:ietf:params:xml:ns:yang:srv6-localsid">
      <localsid>
          <destination>1111:4::2/128</destination>
          <action>End.B6</action>
          <sr-path>
              <srv6-segment>1111:3::2</srv6-segment>
          </sr-path>
          <device>ens192</device>
      </localsid>
    </srv6-localsid>
</config>
</edit-config>
"""

# Single add
result = session.send_rpc(config)
print(format(etree.tostring(result[0], pretty_print=True)))
# Close the session
close_netconf_session(session)
