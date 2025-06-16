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

# 配置ipv6 locator
config_ipv6_locator_xml = """
                <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                <b:srv6 xc:operation="merge" xmlns:b="urn:ietf:params:xml:ns:yang:ietf-srv6-base">
                    <b:encapsulation>
                        <b:source-address></b:source-address>
                    </b:encapsulation>
                    <b:locators>
                    <b:locator>
                        <b:name>h456</b:name>
                        <b:prefix>
                            <b:address>FD10:456::</b:address> 
                            <b:length>96</b:length> 
                        </b:prefix>
                        <b:static-length>3</b:static-length>
                        <b:static>
                            <b:local-sids>
                                 <b:sid>
                                    <b:opcode>3</b:opcode>
                                    <b:end-behavior-type>End_PSP</b:end-behavior-type>
                                </b:sid>
                            </b:local-sids>
                        </b:static>
                    </b:locator>
                    </b:locators>
                </b:srv6>
                </config>  
"""

##all
def test_edit_config(host, port, user, password):
    with h3c_connect(host, port=port, user=user, password=password) as m:
        rpc_obj = m.edit_config(target='running', config=config_ipv6_locator_xml)
        print(rpc_obj)


##main

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    test_edit_config("10.1.2.101", 830, "admin", "mingyang@123")

