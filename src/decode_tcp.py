import struct


def decode_tcp(msg, start_code_source):
	"""
	Decode the tcp part of a message
	Args:
		msg: Message to decode
		start_code_source: Part of the start to decode
	Return:
		por
	"""
	port_source = struct.unpack("!2B",
		msg[start_code_source:start_code_source + 2]
	)

	port_dest = struct.unpack("!2B",
		msg[start_code_source + 2:start_code_source + 4]
	)

	return port_source, port_dest
