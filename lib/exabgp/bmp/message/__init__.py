# encoding: utf-8
"""
message.py

Created by Thomas Mangin on 2013-02-26.
Copyright (c) 2009-2012 Exa Networks. All rights reserved.
"""

from struct import pack

# 0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
# +-+-+-+-+-+-+-+-+
# |    Version    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Message Length                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Msg. Type   |
# +---------------+

class Message (int):
	VERSION = chr(3)  # Yes, this is BMP v7 but the version is still 3

	registered_message = {}
	klass_notify = None

	class ID (int):
		__slots__ = []

		ROUTE       = 0
		STATISTICS  = 1
		PEER_DOWN   = 2
		PEER_UP     = 3
		INITIATION  = 4
		TERMINATION = 5

	_str = {
		chr(ID.ROUTE)       : 'route monitoring',
		chr(ID.STATISTICS)  : 'statistics report',
		chr(ID.PEER_DOWN)   : 'peer down notification',
		chr(ID.PEER_UP)     : 'peer up notification',
		chr(ID.INITIATION)  : 'initiation message',
		chr(ID.TERMINATION) : 'termination message',
	}

	_known = [chr(_) for _ in range (0,6)]

	@staticmethod
	def string (code):
		return Message._str.get(ord(code),'unknown message %d' % code)

	@staticmethod
	def known (code):
		return ord(code) in Message._known

	def __str__ (self):
		return Message._str.get(self,'unknown message %d' % ord(self))

	def validate (self):
		return self in Message._known

	@classmethod
	def register_message (cls,message=None):
		what = cls.TYPE if message is None else message
		if what in cls.registered_message:
			raise RuntimeError('only one class can be registered per capability')
		cls.registered_message[ord(what)] = cls

	@classmethod
	def klass (cls,what):
		if what in cls.registered_message:
			return cls.registered_message[what]
		raise cls.klass_notify('can not handle this bmp message %s' % what)

	@classmethod
	def unpack_message (cls,message,data):
		if message in cls.registered_message:
			return cls.klass(message).unpack_message(data)
		return cls.klass(message).unpack_message(data)

	def _message (self,message):
		return "%s%s%s%s" % (self.VERSION,pack('!I',len(message)+6),chr(self),message)


stat = {
	0: "prefixes rejected by inbound policy",
	1: "(known) duplicate prefix advertisements",
	2: "(known) duplicate withdraws",
	3: "updates invalidated due to CLUSTER_LIST loop",
	4: "updates invalidated due to AS_PATH loop",
}

peer = {
	1: "Local system closed session, notification sent",
	2: "Local system closed session, no notification",
	3: "Remote system closed session, notification sent",
	4: "Remote system closed session, no notification",
}
