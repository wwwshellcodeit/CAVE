# Importing general purpose libraries
import os
import sys

# Importing Payloads and Encoders classess
from payloads import *
from libs.Encoders import *

from libs.Formats import *

def listItem(args):
	if args == "payloads":
		showItem("payloads.")

	elif args == "encoders":
		for m in globals().keys():
			if "Encoder" in m and not "handleEncoder" in m:
				c = globals()[m]
				i = c()
				print(i.info)

	elif args == "formats":
		print("Formats: raw, hex, c, py, exe")

# Internal Function to load classess and show info
def showItem(path):
	mods = [m.__name__ for m in sys.modules.values() if path in m.__name__]
	for mod in mods:
		mod = mod.split(".")[-1]
		m = globals()[mod]
		if "Engine" in mod:
			None
		else:
			init = getattr(m, "Win%s" % mod)
			inf = init()
			print(inf.info)

def handlePayload(args, options=[], output="a"):
	if os.path.isfile(args):
		return
	platform, payload = args.split("_",1)
	payload = payload.title()
	try:
		mod = globals()[payload]
		init = getattr(mod, "Win%s" % payload)
		i = init(output)
		getattr(i, args)(options)
	except Exception:
		print("[x] Provided payload does not exist")
		sys.exit(1)

def handleFormat(formats, output, badchar='', payload=False):
	formats = Formats(formats, output=output, badchar=badchar, payload=payload)
	formats.handle()

def handleEncoder(encoder, output="a", badchar="", payload=False):
	if encoder == False:
		encoder = 'xor'
	lowercase = encoder
	uppercase = encoder.title()
	enc = globals()["%sEncoder" % uppercase]
	e = enc(output=output)
	getattr(e, "%sInit" % lowercase)(badchar, payload=payload)

def clearArtifact(output):
	try:
		os.remove("%s.opcode"%output)
		os.remove("%s.o"%output)
	except Exception:
		None