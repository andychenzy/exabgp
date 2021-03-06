# encoding: utf-8
"""
mp.py

Created by Thomas Mangin on 2012-07-17.
Copyright (c) 2009-2015 Exa Networks. All rights reserved.
"""

from struct import pack
from exabgp.protocol.family import AFI
from exabgp.protocol.family import SAFI
from exabgp.bgp.message.open.capability import Capability

# ================================================================ MultiProtocol
#


class MultiProtocol (Capability,list):
	ID = Capability.CODE.MULTIPROTOCOL

	def __str__ (self):
		return 'Multiprotocol(' + ','.join(["%s %s" % (str(afi),str(safi)) for (afi,safi) in self]) + ')'

	def json (self):
		return '{ "name": "multiprotocol", "families": [%s ] }' % ','.join([' "%s/%s"' % (str(afi),str(safi)) for (afi,safi) in self])

	def extract (self):
		rs = []
		for v in self:
			rs.append(pack('!H',v[0]) + pack('!H',v[1]))
		return rs

	@staticmethod
	def unpack_capability (instance,data,_=None):
		# XXX: FIXME: we should raise if we have twice the same AFI/SAFI
		afi = AFI.unpack(data[:2])
		safi = SAFI.unpack(data[3])
		instance.append((afi,safi))
		return instance

MultiProtocol.register_capability()
