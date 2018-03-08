# Importing general purpose modules
import os
import sys

class Formats:

	def __init__(self, formats, output="a", badchar="", payload=False):
		self.format = formats
		self.output = output
		self.payload = payload

		if os.path.isfile(self.payload):
			opcode = []
			f = open(self.payload,"rb")
			for b in f.read():
				b = '0x%0*X' % (2,b)
				opcode.append(b)
			f.close()
		else:
			with open(self.output+'.opcode', 'r') as infile:
				opcode = []
				for line in infile:
					if "CTOR_LIST__>:" in line:
						break
					tmp = line.split("\t")

					if(len(tmp) > 2):
						opcode.append(tmp[1])

						if badchar:
							if "," in badchar:
								tmp1 = badchar
								tmp0 = str(tmp1).split(",")
								for b in tmp0:
									b = b.replace("0x","")
									if b in tmp[1]:
										print("[!] Can't generate payload with list of given badchar. Try another iteration.")
										sys.exit(0)
							elif not "," in badchar:
								badchar = badchar.replace("0x","")
								if badchar in tmp[1]:
									print("[!] Can't generate payload with list of given badchar. Try another iteration.")
									sys.exit(0)
					
		self.opcode = opcode

	def handle(self):
		self.format = self.format.title()
		try:
			value = getattr(self, "get%s" % self.format)()
			return value
		except Exception:
			print("[x] Provided format does not exist")
			sys.exit(1)

	def toOpcode(self):
		return self.opcode

	def getRaw(self):
		f = open("%s.bin"%self.output,"wb")
		string = ''
		for i in self.opcode:
			i = i.replace('0x','')
			string += i.replace(' ','')
		string = ''.join(a+b for a,b in zip(string[::2],string[1::2]))
		for a,b in zip(string[::2],string[1::2]):
			hexa = bytearray.fromhex(a+b)
			f.write(hexa)
		print("[!] Written %s.bin" % self.output)

	def getHex(self):
		string = ''
		for i in self.opcode:
			i = i.replace('0x','')
			string += i.replace(' ','')
		string = ''.join(a+b for a,b in zip(string[::2],string[1::2]))
		print(string)
		return string

	def getPy(self):
		string = ''
		list1 = []
		for i in self.opcode:
			i = i.replace('0x','')
			string += i.replace(' ', '')
		string = '\\x'.join(a+b for a,b in zip(string[::2], string[1::2]))
		new = "buf = '"
		new += string[:0] + '\\x' + string[0:]+"'"
		print(new)
		return new

	def getC(self):
		string = ''
		list1 = []
		for i in self.opcode:
			i = i.replace('0x','')
			string += i.replace(' ', '')
		string = '\\x'.join(a+b for a,b in zip(string[::2], string[1::2]))
		new = "char buf[] = \""
		new += string[:0] + '\\x' + string[0:]+"\";"
		print(new)
		return new

	def getExe(self):
		new = self.getC()             
		c0 = '''#include<stdio.h>
#include<windows.h>
typedef void (*DEPBye)();
int main(){
	DEPBye func;
	%s
	func = (int(*)()) VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(func, buf, sizeof(buf));
	(*func)();
	VirtualFree(func, NULL, MEM_RELEASE);
	return 0;
}''' % (new)
		final = open("%s.c" % self.output,"w")
		final.write(c0)
		final.close()
		os.system("i586-mingw32msvc-gcc %s.c -o %s.exe -Wl,--subsystem,windows -fno-stack-protector 2> /dev/null" % (self.output, self.output))
		os.remove("%s.c" % self.output)
		print("[!] Generating %s.exe" % self.output)
		os.system("i586-mingw32msvc-objcopy %s.exe --writable-text" % self.output)

	# Internal function; return 0x64, 0x8b, ...
	def getString0(self):
		string = ''
		list1 = []
		for i in self.opcode:
			i = i.replace('0x',' ')
			string += i.replace(' ', '')
		string = ', 0x'.join(a+b for a,b in zip(string[::2], string[1::2]))
		new = ""
		new += string[:0] + '0x' + string[0:]
		return new

	# Internal function; return \x55\x89...
	def getString1(self):
		string = ''
		list1 = []
		for i in self.opcode:
			i = i.replace('0x',' ')
			string += i.replace(' ', '')
		string = '\\x'.join(a+b for a,b in zip(string[::2], string[1::2]))
		new = ""
		new += string[:0] + '\\x' + string[0:]
		return new