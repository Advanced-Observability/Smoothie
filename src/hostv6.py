#  Copyright 2019-present Open Networking Foundation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from mininet.node import CPULimitedHost
import ipaddress
from p4utils.mininetlib.log import debug, info, output, warning, error, critical



class IPv6Host(CPULimitedHost):

    def config(self, ipv6, ipv6_gw=None, **params):
        r = super(IPv6Host, self).config(**params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr add %s dev %s' % (ipv6, self.defaultIntf()))
        if ipv6_gw:
            self.cmd('ip -6 route add default via %s' % ipv6_gw)

        for off in ['rx', 'tx', 'sg']:
            cmd = '/sbin/ethtool --offload {} {} off'.format(
                self.defaultIntf().name, off)
            self.cmd(cmd)

        def updateIP():
            return ipv6.split('/')[0]
        self.defaultIntf().updateIP = updateIP

        return r

    def terminate(self):
        # self.cmd( 'sysctl -w net.ipv6.conf.all.forwarding=0' )
        super(IPv6Host, self).terminate()

    def describe(self, sw_addr=None, sw_mac=None):
        """Describes host."""

        output('**********\n')
        output('Network configuration for: {}\n'.format(self.name))
        output('Default interface: {}\t{}\t{}\n'.format(
               self.defaultIntf().name,
               self.defaultIntf().IP(),
               self.defaultIntf().MAC()
               ))
        if sw_addr is not None or sw_mac is not None:
            output('Default route to switch: {} ({})\n'.format(sw_addr, sw_mac))
        output('**********\n')


class SRv6Host(IPv6Host):

    ipv6 = ipaddress.IPv6Address('2001:1:1::b')

    def config(self, ipv6=str(ipv6)+'/64', ipv6_gw=None, **params):
        super(IPv6Host, self).config(**params)
        # Enable SRv6
        self.cmd('sysctl -w net.ipv6.conf.all.seg6_enabled=1')
        self.cmd('sysctl -w net.ipv6.conf.%s.seg6_enabled=1' % self.defaultIntf())
        self.ipv6 = self.ipv6+1 