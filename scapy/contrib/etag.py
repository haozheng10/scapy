# Copyright (C) 2018 Hao Zheng <haozheng10@gmail.com>

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = E-TAG
# scapy.contrib.status = loads

"""
E-TAG Virtual Bridged Local Area Networks Bridge Port Extension

[IEEE Std 802.1BR 2012]
"""

from scapy.config import conf
from scapy.data import *
from scapy.fields import BitField, XByteField, XShortEnumField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *

class ETag(Packet):
    name = "802.1BR"
    aliastypes = [ Ether ]
    fields_desc = [ BitField("pcp", 0, 3),
                    BitField("dei", 0, 1),
                    BitField("iecid_base", 0, 12),
                    BitField("reserved", 0, 2),
                    BitField("grp", 0, 2),
                    BitField("ecid_base", 0, 12),
                    XByteField("iecid_ext", 0),
                    XByteField("ecid_ext", 0),
                    XShortEnumField("type", 0x0000, ETHER_TYPES) ]
    def _calc_cids(self):
        iecid = self.iecid_base | self.iecid_ext << 12
        ecid = self.ecid_base | self.ecid_ext << 12 | self.grp << 20
        return iecid, ecid
    def answers(self, other):
        if isinstance(other, ETag):
            iecid, ecid = self._calc_cids()
            o_iecid, o_ecid = other._calc_cids()
            if ( (self.type == other.type) and
                 (iecid == o_iecid) and
                 (ecid == o_ecid) ):
                return self.payload.answers(other.payload)
        else:
            return self.payload.answers(other)
        return 0
    def default_payload_class(self, pay):
        if self.type <= 1500:
            return LLC
        return conf.raw_layer
    def extract_padding(self,s):
        if self.type <= 1500:
            return s[:self.type],s[self.type:]
        return s,None
    def mysummary(self):
        iecid, ecid = self._calc_cids()
        if isinstance(self.underlayer, Ether):
            return self.underlayer.sprintf("802.1br %Ether.src% > %Ether.dst% (%ETag.type%)") + \
                   " iecid 0x{:x} ".format(iecid) + \
                   " ecid 0x{:x}".format(ecid)
        else:
            return self.sprintf("802.1br (%ETag.type%)") + \
                   " iecid 0x{:x} ".format(iecid) + \
                   " ecid 0x{:x}".format(ecid)


conf.neighbor.register_l3(Ether, ETag, l2_register_l3)

bind_layers(Ether, ETag, type=0x893f)
bind_layers(ETag, Dot1AD, type=0x88a8)
bind_layers(ETag, Dot1Q, type=0x8100)
bind_layers(CookedLinux, ETag, proto=0x893f)
bind_layers(SNAP, ETag, code=0x893f)
