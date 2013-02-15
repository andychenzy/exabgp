#!/usr/bin/env python


header = [
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, # marker
	0x1, 0x37, # len 311 (body is 296 - 296 + 19 = 315 !!)
	0x2, # type Update
]

body = [
	0x0, 0x0, #len withdrawn routes
	# No routes to remove
	# Attributes
	0x0, 0x30, # len attributes (48)
		0x40, # Flag Transitive
		0x1, # Code : AttributeID Origin
		0x1, # len
			0x0, # Origin : IGP
		0x50, # Flag Transitive + extended length
		0x2, # Code : AS Path
		0x0, 0x16, # len 22
			0x2, # Type (AS_Sequence)
			0x5, # length (in ASes as every asn is 0x0 0x0 prefixed ASN4 must have been negotiated)
				0x0, 0x0, 0xfe, 0xb0,		# ASN 65200
				0x0, 0x0, 0x78, 0x14,		# ASN 30740
				0x0, 0x0, 0x19, 0x35,		# ASN 6453
				0x0, 0x0, 0xb, 0x62,		# ASN 2914
				0x0, 0x0, 0x9, 0xd7,		# ASN 2519
		0x40, # Flag Transitive
		0x3, # Code: Next HOP
		0x4, # len
			0x7f, 0x0, 0x0, 0x1, # 127.0.0.1
		0xc0, # 0x40 + 0x80 (Transitive Optional)
		0x8, # Community
		0x8, # Size 8
			0x78, 0x14, 0x19, 0x35, # 30740:6453
			0x78, 0x14, 0xfd, 0xeb, # 30740:65003
	# routes :
		0x18, 0x1, 0x0, 0x19, # 1.0.25.0/24
		0x10, 0xde, 0xe6, # 222.330.0.0/16
		0x11, 0xde, 0xe5, 0x80,
		0x12, 0xde, 0xe5, 0x0,
		0x10, 0xde, 0xe4,
		0x11, 0xdc, 0xf7, 0x0,
		0x11, 0xdc, 0x9e, 0x0,
		0x18, 0xdb, 0x79, 0xff,
		0x18, 0xdb, 0x79, 0xf9,
		0x16, 0xd8, 0xb3, 0xcc,
		0x18, 0xd8, 0xb3, 0xb6,
		0x17, 0xd8, 0xb3, 0xb4,
		0x16, 0xd8, 0xb3, 0xb0,
		0x18, 0xd8, 0xb3, 0x99,
		0x12, 0xd2, 0xaa, 0x0,
		0x11, 0xd2, 0x92, 0x80,
		0x11, 0xd2, 0x83, 0x80,
		0x13, 0xcb, 0x8c, 0x20,
		0x18, 0xca, 0xf5, 0xfe,
		0x18, 0xca, 0xf5, 0x8e,
		0x18, 0xca, 0xf3, 0xba,
		0x18, 0xca, 0xf0, 0x8d,
		0x12, 0xca, 0xef, 0xc0,
		0x12, 0xca, 0xe7, 0x40,
		0x10, 0xca, 0xd7,
		0x18, 0xca, 0xd2, 0x8,
		0x13, 0xca, 0xbd, 0xc0,
		0x14, 0xca, 0x58, 0x30,
		0x18, 0xca, 0x22, 0xbf,
		0x17, 0xca, 0x22, 0x96,
		0x18, 0xc0, 0x32, 0x6e,
		0x10, 0xb7, 0xb4,
		0x11, 0xb7, 0xb1, 0x80,
		0x10, 0xa3, 0x8b,
		0x11, 0x9d, 0x78, 0x80,
		0x15, 0x7c, 0xf1, 0x78,
		0x10, 0x7c, 0x6e,
		0x10, 0x7a, 0x67,
		0x10, 0x78, 0x33,
		0x10, 0x74, 0x5b,
		0x15, 0x73, 0xbb, 0x48,
		0x16, 0x73, 0xbb, 0x44,
		0x10, 0x73, 0xb3,
		0x11, 0x72, 0x45, 0x0,
		0x14, 0x71, 0x34, 0xf0,
		0x15, 0x70, 0x6d, 0x18,
		0x18, 0x67, 0xf6, 0xb3,
		0x17, 0x67, 0xb, 0x6,
		0x18, 0x67, 0x5, 0x75,
		0x18, 0x67, 0x5, 0x74,
		0x18, 0x67, 0x3, 0x10,
		0x13, 0x65, 0x37, 0xc0,
		0x11, 0x65, 0x32, 0x80,
		0x18, 0x65, 0x0, 0x1f,
		0x18, 0x65, 0x0, 0x1e,
		0x18, 0x65, 0x0, 0x1d,
		0x18, 0x65, 0x0, 0x1c,
		0xf, 0x24, 0x2,
		0x11, 0x1b, 0x79, 0x80,
		0x13, 0x1b, 0x60, 0x20,
		0x15, 0x1b, 0x60, 0x10,
		0x10, 0x1, 0x15,
		0x16, 0x1, 0x0, 0x1c,
		0x17, 0x1, 0x0, 0x1a
]


header = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1, 0x22, 0x2]

body = [
	0x0, 0x0,
	0x0, 0x38,
	0x40,
		0x1,
		0x1,
			0x0,
	0x50,
		0x2,
		0x0, 0x12,
			0x2,
			0x4,
				0x0, 0x0, 0xc7, 0x9d,
				0x0, 0x0, 0x9b, 0xbd,
				0x0, 0x0, 0xb, 0x62,
				0x0, 0x0, 0x9, 0xd7,
	0x40,
		0x3,
		0x4,
			0xb2, 0xd9, 0x76, 0x1,
	0xc0,
		0x8,
		0x14,
			0xb, 0x62, 0x1, 0x9a,
			0xb, 0x62, 0x5, 0x7b,
			0xb, 0x62, 0x9, 0x61,
			0xb, 0x62, 0xd, 0x48,
			0x9b, 0xbd, 0x1d, 0x1a,
	0x18, 0x1, 0x0, 0x19,
	0x10, 0xde, 0xe6,
	0x11, 0xde, 0xe5, 0x80,
	0x12, 0xde, 0xe5, 0x0,
	0x18, 0xdb, 0x79, 0xff,
	0x18, 0xdb, 0x79, 0xf9,
	0x16, 0xd8, 0xb3, 0xcc,
	0x18, 0xd8, 0xb3, 0xb6,
	0x17, 0xd8, 0xb3, 0xb4,
	0x16, 0xd8, 0xb3, 0xb0,
	0x18, 0xd8, 0xb3, 0x99,
	0x12, 0xd2, 0xaa, 0x0,
	0x11, 0xd2, 0x92, 0x80,
	0x11, 0xd2, 0x83, 0x80,
	0x13, 0xcb, 0x8c, 0x20,
	0x18, 0xca, 0xf5, 0xfe,
	0x18, 0xca, 0xf5, 0x8e,
	0x18, 0xca, 0xf3, 0xba,
	0x18, 0xca, 0xf0, 0x8d,
	0x12, 0xca, 0xef, 0xc0,
	0x12, 0xca, 0xe7, 0x40,
	0x18, 0xca, 0xd2, 0x8,
	0x13, 0xca, 0xbd, 0xc0,
	0x14, 0xca, 0x58, 0x30,
	0x18, 0xca, 0x22, 0xbf,
	0x17, 0xca, 0x22, 0x96,
	0x18, 0xc0, 0x32, 0x6e,
	0x10, 0xb7, 0xb4,
	0x11, 0x9d, 0x78, 0x80,
	0x15, 0x7c, 0xf1, 0x78,
	0x10, 0x7a, 0x67,
	0x15, 0x73, 0xbb, 0x48,
	0x16, 0x73, 0xbb, 0x44,
	0x11, 0x72, 0x45, 0x0,
	0x14, 0x71, 0x34, 0xf0,
	0x15, 0x70, 0x6d, 0x18,
	0x18, 0x67, 0xf6, 0xb3,
	0x17, 0x67, 0xb, 0x6,
	0x18, 0x67, 0x5, 0x75,
	0x18, 0x67, 0x5, 0x74,
	0x18, 0x67, 0x3, 0x10,
	0x13, 0x65, 0x37, 0xc0,
	0x11, 0x65, 0x32, 0x80,
	0x18, 0x65, 0x0, 0x1f,
	0x18, 0x65, 0x0, 0x1e,
	0x18, 0x65, 0x0, 0x1d,
	0x18, 0x65, 0x0, 0x1c,
	0xf, 0x24, 0x2,
	0x11, 0x1b, 0x79, 0x80,
	0x13, 0x1b, 0x60, 0x20,
	0x15, 0x1b, 0x60, 0x10,
	0x10, 0x1, 0x15,
	0x16, 0x1, 0x0, 0x1c,
	0x17, 0x1, 0x0, 0x1a
]

route = header + body

from StringIO import StringIO
from exabgp.bgp.protocol import Protocol
from exabgp.bgp.peer import Peer
from exabgp.bgp.neighbor import Neighbor

class Connection (StringIO):
	def pending (self,**argv):
		return True

cnx = Connection(''.join([chr(_) for _ in route]))
neibor = Neighbor()
peer = Peer(neibor,None)

#import pdb
#pdb.set_trace()

proto = Protocol(peer,cnx)
proto._asn4 = True
print proto.UpdateFactory(body)
