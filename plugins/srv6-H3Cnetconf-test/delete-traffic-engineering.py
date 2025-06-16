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


# 删除traffic-engineering
delete_traffic_engineering_xml = """
                <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <top xmlns="http://www.h3c.com/netconf/config:1.0">
                        <segment-routing-ipv6 xc:operation="delete">
                            <traffic-engineering>
                                <attributes>
                                    <segment-lists>
                                        <segment-list>  
                                            <name>test</name>
                                        </segment-list>
                                    </segment-lists>
                                </attributes>
                                <policies>
                                    <policy>
                                        <color>30</color>
                                        <endpoint>FD10:333::5</endpoint>
                                    </policy>
                                </policies>
                            </traffic-engineering>
                        </segment-routing-ipv6>
                    </top>
                </config>

"""


##all
def test_edit_config(host, port, user, password):
    with h3c_connect(host, port=port, user=user, password=password) as m:
        rpc_obj = m.edit_config(target='running', config=delete_traffic_engineering_xml)
        print(rpc_obj)


##main

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    test_edit_config("10.1.2.101", 830, "admin", "mingyang@123")

