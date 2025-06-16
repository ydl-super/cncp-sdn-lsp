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


# 配置traffic-engineering

config_traffic_engineering_xml = """
                <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <top xmlns="http://www.h3c.com/netconf/config:1.0">
                        <segment-routing-ipv6 xc:operation="merge">
                            <traffic-engineering>
                                <attributes>
                                    <locator>h1</locator>
                                    <segment-lists>
                                        <segment-list>  
                                            <name>test</name>
                                            <segments>
                                                <segment>
                                                    <index>10</index>
                                                    <type>2</type>
                                                    <segment-types>
                                                        <segment-type-2>
                                                            <sid-value>FD10:2::1</sid-value>
                                                        </segment-type-2>
                                                    </segment-types>
                                                </segment>
                                                <segment>
                                                    <index>30</index>
                                                    <type>2</type>
                                                    <segment-types>
                                                        <segment-type-2>
                                                            <sid-value>FD10:3::1</sid-value>
                                                        </segment-type-2>
                                                    </segment-types>
                                                </segment>
                                            </segments>
                                        </segment-list>
                                    </segment-lists>
                                </attributes>
                                <policies>
                                    <policy>
                                        <color>30</color>
                                        <endpoint>FD10:333::5</endpoint>
                                        <name>test</name>
                                        <binding-sid>
                                            <dataplane>2</dataplane>
                                            <value>FD10:1::3</value>
                                        </binding-sid>
                                        <candidate-paths>
                                            <candidate-path>
                                                <protocol-origin>30</protocol-origin>
                                                <originator/>
                                                <discriminator>40</discriminator>
                                                <preference>40</preference>
                                                <segment-lists>
                                                    <segment-list>
                                                        <name-ref>test</name-ref>
                                                    </segment-list>
                                                </segment-lists>
                                            </candidate-path>
                                        </candidate-paths>
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
        rpc_obj = m.edit_config(target='running', config=config_traffic_engineering_xml)
        print(rpc_obj)


##main

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    test_edit_config("10.1.2.101", 830, "admin", "mingyang@123")

