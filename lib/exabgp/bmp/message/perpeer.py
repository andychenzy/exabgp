# encoding: utf-8
"""
message.py

Created by Thomas Mangin on 2013-02-26.
Copyright (c) 2009-2012 Exa Networks. All rights reserved.
"""

from exabgp.protocol.family import AFI

from exabgp.bgp.message.open.asn import ASN
from exabgp.bgp.message.update.nlri.qualifier.rd import Distinguisher

from struct import pack,unpack

# 0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Peer Type   |  Peer Flags   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Peer Distinguisher (present based on peer type)       |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                 Peer Address (16 bytes)                       |
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Peer AS                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Peer BGP ID                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Timestamp (seconds)                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Timestamp (microseconds)                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class Flag (object):
	V_FLAG = 0b10000000  # set if the address is IPv6, otherwise IPv4
	V_MASK = 0b01111111

	L_FLAG = 0b01000000  # set if the data decoded is post filtering policy
	L_MASK = 0b10111111

	def __init__ (self,bits):
		self.bits = bits
		# self.bits  = self.V_FLAG if ipv6   else 0
		# self.bits += self.L_FLAG if policy else 0

	def _isipv4 (self):
		return bool(self.bits & ~self.V_FLAG)

	def _setipv4 (self,boolean):
		if boolean:
			self.bits &= self.V_MASK
		else:
			self.bits |= self.V_FLAG
		return self

	def _isipv6 (self):
		return bool(self.bits & self.V_FLAG)

	def _setipv6 (self,boolean):
		if boolean:
			self.bits |= self.V_FLAG
		else:
			self.bits &= self.V_MASK
		return self

	def _haspolicy (self):
		return bool(self.bits & self.L_FLAG)

	def _setpolicy (self,boolean):
		if boolean:
			self.bits |= self.L_FLAG
		else:
			self.bits &= self.L_MASK
		return self

	ipv4 = property(_isipv4,_setipv4)
	ipv6 = property(_isipv6,_setipv6)
	policy = property(_haspolicy,_setpolicy)

	def pack (self):
		return chr(self.bits)

	def __str__ (self):
		return 'flag ipv%d %s-policy'  % (6 if self.ipv6 else 4, 'post' if self.policy else 'pre')


class Type (int):
	def internet (self):
		return self == 0

	def vpn (self):
		return self == 1

	def pack (self):
		return chr(self)


class PeerDistinguisher (Distinguisher):
	TYPE = 'peer'


class Address (str):
	filled = chr(0)*12

	def afi (self):
		return AFI.ipv4 if self.startswith(self.filled) else AFI.ipv6

	def ipv4 (self):
		raise NotImplemented('TSS TSS')

	def ipv6 (self):
		raise NotImplemented('TSS TSS')

	def ip (self):
		return self.ipv6() if self.afi() == AFI.IPv6 else self.ipv4()

	def pack (self):
		return self




class PerPeer (object):
	def __init__ (self,what,flag,distinguisher,address,asn,bgpid,second,microsecond):
		self.what = what
		self.flag = Flag(flag)
		self.distinguisher = distinguisher
		self.address = address
		self.asn = asn
		self.bgpid = self.bgpid
		self.second = second
		self.microsecond = microsecond

	@classmethod
	def unpack_message (cls,message):
		values = unpack('!BBHHHHQIIII')
		return cls(
			Type(values[0]),
			Flag(value[1]),
			PeerDistinguisher(message[2:10]),
			Address(message[10:26]),
			ASN(value[26]),
			values[-2],
			values[-1]
		)
