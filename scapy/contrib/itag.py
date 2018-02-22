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

# scapy.contrib.description = I-TAG
# scapy.contrib.status = loads

"""
I-TAG Backbone Service Instance Tag
      Bridges and Bridged Networks

[IEEE Std 802.1Q 2014]
"""

from scapy.config import conf
from scapy.data import *
from scapy.fields import BitField, XByteField, XShortEnumField, X3BytesField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *

class ITag(Packet):
    name = "I-Tag"
    aliastypes = [ Ether ]
    fields_desc = [ BitField("ipcp", 0, 3),
                    BitField("idei", 0, 1),
                    BitField("uca", 0, 1),
                    BitField("res1", 0, 1),
                    BitField("res2", 0, 2),
                    X3BytesField("isid", 0),
                    DestMACField("cda"),
                    SourceMACField("csa"),
                    XShortEnumField("type", 0x0000, ETHER_TYPES) ]
    def answers(self, other):
        if isinstance(other, ITag):
            if ( (self.type == other.type) and
                 (self.isid == other.isid) and
                 (self.uca == other.uca) ):
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
        return self.sprintf("I-Tag (I-SID %isid% UCA %uca% C-SA %csa% > C-DA %cda% (%type%))")


bind_layers(Dot1Q, ITag, type=0x88e7)
bind_layers(ITag, Dot1Q, type=0x8100)
