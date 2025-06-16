import sys
import logging
from ncclient import manager
from ncclient import operations


log = logging.getLogger(__name__)


##connect device
def h3c_connect(host, port, user, password):
    return manager.connect(host=host,
                           port=port,
                           username=user,
                           password=password,
                           hostkey_verify=False,
                           device_params={'name': "h3c"},
                           allow_agent=False,
                           look_for_keys=False)


# 配置bgp_locator
#address-family ipv6 unicast
#network FD10:111:: 120
config_bgp_network_xml = """
                <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <top xmlns="http://www.h3c.com/netconf/config:1.0">
                        <BGP>
                            <Networks>
                                <Network>
                                    <Name></Name>
                                    <VRF></VRF>
                                    <Family>5</Family>
                                    <IpAddress>FD10:456::</IpAddress>
                                    <Mask>120</Mask>
                                </Network>
                            </Networks>
                        </BGP>
                    </top>
                </config>

"""


##all
def test_edit_config(host, port, user, password):
    with h3c_connect(host, port=port, user=user, password=password) as m:
        rpc_obj = m.edit_config(target='running', config=config_bgp_network_xml)
        print(rpc_obj)


##main

if __name__ == '__main__':
    test_edit_config("10.1.2.101", 830, "admin", "mingyang@123")

