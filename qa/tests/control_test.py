#!/usr/bin/env python

import time
import socket
import tempfile
import unittest
from multiprocessing import Process

from exabgp.reactor.api.control import Control


from exabgp.configuration.setup import environment
env = environment.setup('')


def speak (name,data):
	time.sleep(0.005)
	try:
		sock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
		sock.connect(name)
		sock.sendall(data)
	except socket.error:
		pass


class TestControl (unittest.TestCase):
	def setUp (self):
		pass

	def test_failed_creation (self):
		control = Control()
		try:
			result = control.init()
			assert result is False
		except IOError:
			# could not write in the location
			pass
		finally:
			control.cleanup()

	def validate (self,message,check):
		name = tempfile.mktemp()
		control = Control(name,False)
		try:
			result = control.init()
			assert result is True

			p = Process(target=speak, args=(name,message))
			p.start()

			string = control.loop()
			assert string == check
			p.join()
		finally:
			control.cleanup()
			del control

	def test_no_newline (self):
		self.validate('x','')

	def test_one_newline (self):
		self.validate('x\n','x')

	def test_two_newline (self):
		self.validate('-\nx\n','x')

	def test_leftover (self):
		self.validate('-\nx\n-','x')

if __name__ == '__main__':
	unittest.main()
