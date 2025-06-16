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


# 获取bgp_network
get_bgp_network_xml = """
                <top xmlns="http://www.h3c.com/netconf/data:1.0">
                    <BGP>
                        <Networks>
                            <Network>
                                <Name></Name>
                                <VRF></VRF>
                                <Family></Family>
                                <IpAddress></IpAddress>
                                <Mask></Mask>
                            </Network>
                        </Networks>
                    </BGP>
                </top>

"""


##all
def test_edit_config(host, port, user, password):
    with h3c_connect(host, port=port, user=user, password=password) as m:
        get_reply = m.get(("subtree", get_bgp_network_xml)).data_xml
        print(get_reply)


##main

if __name__ == '__main__':
    test_edit_config("10.1.2.101", 830, "admin", "mingyang@123")

