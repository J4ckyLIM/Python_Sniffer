import socket
import struct
import time


def decode(msg):
	mac_dst = struct.unpack('!6B', msg[0:6])
	mac_dst = ":".join([hex(part)[2:].zfill(2) for part in mac_dst])
	mac_src = struct.unpack('!6B', msg[6:12])
	mac_src = ":".join([hex(part)[2:].zfill(2) for part in mac_src])
	ether_type = struct.unpack('!H', msg[12:14])
	ether_type = ":".join([hex(part)[2:].zfill(4) for part in ether_type])

	if ether_type == "0800":
		protocole = struct.unpack('!BB', msg[23:25])
		protocole = ":".join([hex(part)[2:].zfill(2) for part in protocole])
		ip_source = struct.unpack('!4B', msg[26:30])
		ip_source = ".".join(str(part) for part in ip_source)
		ip_destination = struct.unpack('!4B', msg[30:34])
		ip_destination = ".".join(str(part) for part in ip_destination)

		print(f"IP_SRC: {ip_source}")
		print(f"IP_DST: {ip_destination}")
		print(f"PROTOCOLE: {protocole}")

	print(
		f"{time.time()}: DST_MAC: {mac_dst} - "
		f"SRC_MAC: {mac_src} - "
		f"ETHER_TYPE: {ether_type} - "
	)


def main():
	"""Entry point"""
	s = socket.socket(
		socket.AF_PACKET,
		socket.SOCK_RAW,
		socket.htons(3),
	)
	s.bind(("enp0s29u1u1c4i2", 3))
	try:
		print("Sniffer started")
		while True:
			msg = s.recv(1024)
			decode(msg)
	except KeyboardInterrupt:
		print("Sniffer stopped")


if __name__ == "__main__":
	main()
