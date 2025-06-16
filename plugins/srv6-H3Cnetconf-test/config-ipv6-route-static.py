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


# 配置ipv6_route_static_

config_ipv6_route_static_xml = """
                <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <top xmlns="http://www.h3c.com/netconf/config:1.0">
                        <StaticRoute xc:operation="merge">
                            <SrPolicyRouteEntries>
                                <RouteEntry>
                                    <VrfName/>
                                    <Prefix>10.10.3.0</Prefix>
                                    <PrefixLength>24</PrefixLength>
                                    <SrAfType>ipv6</SrAfType>
                                    <PolicyName/>
                                    <Color>30</Color>
                                    <Endpoint>FD10:333::5</Endpoint>
                                    <Preference>40</Preference>
                                    <Tag>1</Tag>
                                    <Sid>::</Sid>
                                </RouteEntry>
                            </SrPolicyRouteEntries>
                            <Srv6PolicyRouteEntries>
                                <RouteEntry>
                                    <VrfName/>
                                    <Prefix>6789::</Prefix>
                                    <PrefixLength>120</PrefixLength>
                                    <SrAfType>ipv6</SrAfType>
                                    <PolicyName/>
                                    <Color>30</Color>
                                    <Endpoint>FD10:333::5</Endpoint>
                                    <Preference>40</Preference>
                                    <Tag>1</Tag>
                                    <Sid>::</Sid>
                                </RouteEntry>
                            </Srv6PolicyRouteEntries>
                        </StaticRoute>
                    </top>
                </config>

"""


##all
def test_edit_config(host, port, user, password):
    with h3c_connect(host, port=port, user=user, password=password) as m:
        rpc_obj = m.edit_config(target='running', config=config_ipv6_route_static_xml)
        print(rpc_obj)


##main

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    test_edit_config("10.1.2.101", 830, "admin", "mingyang@123")

