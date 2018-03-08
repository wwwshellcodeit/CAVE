import argparse
import sys
from libs.Arguments import listItem, handlePayload, handleFormat, handleEncoder, clearArtifact

if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage="python3 Cerberus.py [options]")

    parser.add_argument("-p", "--payload", 	dest="payload", default=False, 		help="Select Payload or Import Binary File")
    parser.add_argument("-e", "--encoder", 	dest="encoder", default=False, 		help="Select Encoder")
    parser.add_argument("-f", "--format", 	dest="format", 	default='', 		help="Select Format")
    parser.add_argument("-l", "--list", 	dest="list", 	default=False,		help="List: -l payloads,encoders,formats")
    parser.add_argument("-b", "--badchar", 	dest="badchar", default='', 		help="Example: -b 0x00,0xff")
    parser.add_argument("-o", "--output",	dest="output",	default="a",		help="Specify output file; example: backdoor")

    args, options = parser.parse_known_args()

    if args.list:
    	listItem(args.list)
    	sys.exit(0)
    	
    if args.payload and not (args.encoder or args.badchar):
    	handlePayload(args.payload, options=options, output=args.output)
    	handleFormat(args.format, args.output, payload=args.payload)
    elif args.payload and (args.encoder or args.badchar):
    	handlePayload(args.payload, options=options, output=args.output)
    	handleEncoder(args.encoder, output=args.output, badchar=args.badchar, payload=args.payload)
    	handleFormat(args.format, args.output, badchar=args.badchar)

    clearArtifact(args.output)