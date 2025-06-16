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

##获取配置
IF_GET_RPC = """
                <b:srv6 xmlns:b="urn:ietf:params:xml:ns:yang:ietf-srv6-base">
                    <b:encapsulation>
                        <b:source-address></b:source-address>
                    </b:encapsulation>
                    <b:locators>
                    </b:locators>
                </b:srv6>  
"""
##all
def test_get(host, port, user, password):
    with h3c_connect(host, port=port, user=user, password=password) as m:
        get_reply = m.get(("subtree", IF_GET_RPC)).data_xml
        print(get_reply)


##main

if __name__ == '__main__':
    test_get("10.1.2.101", 830, "admin", "mingyang@123")

