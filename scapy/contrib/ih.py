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
I-TAG Backbone Service Instance Tag, formerly Provider Backbone Bridge
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

class IH(Packet):
    name = "InstructionHeader"
    aliastypes = [ Ether ]
    fields_desc = [ XBitField("w", 1, 1),
                    XBitField("raw", 0, 1),
                    XBitField("utag", 1, 1),
                    XBitField("uqpg", 1, 1),
                    XBitField("zero1", 0, 1),
                    XBitField("pm", 0, 3),
                    XByteField("sl", 8),
                    XBitField("utt", 1, 1),
                    XBitField("tt", 0, 2),
                    XBitField("zero2", 0, 2),
                    XBitField("qpg", 0, 11),
                    XLongField("tag", 0) ]
    def default_payload_class(self, payload):
        if len(payload) >= 14:
            return Ether
        return Padding
