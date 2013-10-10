import os
import shutil
import subprocess

class ownPKI:
	def __init__(self, name, crtUrl, crlUrl):
		self.name = name
		self.crlUrl = crlUrl
		self.crtUrl = crtUrl
		if not os.path.exists('serial'):
			self.serial = 1
		else:
			f = open('serial', 'r')
			self.serial = int(f.read())
			f.close()
			del f
			if self.serial <= 1:
				raise Exception('Serial is too small.')
				
	def getKeyArgs(self, name):
		args = ['ownPKI', 'newKey']
		args += ['-rnd', 'rnd', '-out', name + '.pub', '-key', 'private/' + name + '.key']
		if not hasattr(self, 'password'):
			args += ['-passin']
		else:
			args += ['-pass', self.password]
		return args
	
	def getSignArgs(self, cmd, C, CN, name = None, usage = None, dns = None):
		args = ['ownPKI', cmd]
		args += ['-rnd', 'rnd', '-ca', self.name + '.crt', '-caKey', 'private/' + self.name + '.key']
		if not hasattr(self, 'password'):
			args += ['-passin']
		else:
			args += ['-pass', self.password]
		args += ['-C', C, '-CN', CN]
		args += ['-caCrlUrl', self.crlUrl]
		if not name is None:
			args += ['-caCrtUrl', self.crtUrl, '-key', name + '.pub', '-out', name + '.crt']
		if not usage is None:
			args += ['-usage', usage]
		if not dns is None:
			args += ['-dns', dns]
		args += ['-serial', str(self.serial)]
		return args
		
	def incSerial(self):
		self.serial = self.serial + 1
		f = open('serial', 'w')
		f.write(str(self.serial))
		f.flush()
		f.close()
		
	def crtSigned(self, name, C, CN, usage):
		serial = self.serial
		
		self.incSerial()

		f = open('signed', 'a')
		f.write(str(serial) + '\t' + name + '\t' + C + '\t' + CN + '\t' + usage + '\n')
		f.flush()
		f.close()

		shutil.copy(name + '.crt', 'certs/' + str(serial) + '.crt')
		
	def createKey(self, name):
		if not os.path.isdir('private'):
			os.makedirs('private')
		subprocess.call(self.getKeyArgs(name))
		
	def newRoot(self, C, CN):
		if not os.path.isdir('private'):
			os.makedirs('private')
		if not os.path.isdir('certs'):
			os.makedirs('certs')

		if not os.path.exists(self.name + '.key'):
			print 'creating new key ...'
			subprocess.call(self.getKeyArgs(self.name))
		if os.path.exists(self.name + '.crt'):
			raise Exception('CA-Certificate already exists.')
		self.serial = 1
		print 'creating ca...'
		r = subprocess.call(self.getSignArgs('rootCA', C, CN))
		if r != 0:
			raise Exception('ownPKI ended badly.', r)
		self.incSerial()
		
	def sign(self, name, C, CN, usage = 'ca', dns = None):
		r = subprocess.call(self.getSignArgs('sign', C, CN, name, usage, dns))
		if r != 0:
			raise Exception('ownPKI ended badly.', r)
		self.crtSigned(name, C, CN, usage)
