import socket
import struct
import time
from src import helpers


def decode(msg):

	mac_dst = struct.unpack('!6B', msg[0:6])
	mac_dst = helpers.convert_int_list_to_exa_string(mac_dst)

	mac_src = struct.unpack('!6B', msg[6:12])
	mac_src = helpers.convert_int_list_to_exa_string(mac_src)

	ether_type = struct.unpack('!H', msg[12:14])
	ether_type = helpers.convert_int_list_to_exa_string(ether_type, 4)
	print(
		f"{time.time()}: DST_MAC: {mac_dst} - "
		f"MAC_SRC: {mac_src} - "
		f"ETHER_TYPE: {ether_type} - "
	)

	if ether_type == "0800":
		protocole = struct.unpack('!B', msg[23:24])
		protocole = protocole[0]
		print(f"PROTOCOLE: {protocole}")

		ip_source = struct.unpack('!4B', msg[26:30])
		ip_source = helpers.convert_int_list_to_string(ip_source)
		print(f"ip_source: {ip_source}")

		ip_destination = struct.unpack('!4B', msg[30:34])
		ip_destination = helpers.convert_int_list_to_string(ip_destination)
		print(f"IP_DST: {ip_destination}")

	if ether_type == "0806":
		protocole = struct.unpack('!2B', msg[16:18])
		protocole = protocole[0]
		print(f"PROTOCOLE: {protocole}")

		sender_ha = struct.unpack('!6B', msg[23:29])
		sender_ha = helpers.convert_int_list_to_exa_string(sender_ha)
		print(f"Sender_HA: {sender_ha}")

		sender_ia = struct.unpack('!4B', msg[29:33])
		print(f"Sender_IA: {sender_ia}")

		tha = struct.unpack('!6B', msg[33:39])
		tha = helpers.convert_int_list_to_exa_string(tha)
		print(f"TARGET HA: {tha}")

		tia = struct.unpack('!3B', msg[39:42])
		print(f"TARGET IA: {tia}")

	if protocole == "6":
		port_source = struct.unpack('!2B', msg[0:2])
		port_dest = struct.unpack('!2B', msg[2:4])
		print(f"PORT_SRC: {port_source}")
		print(f"PORT_DEST: {port_dest}")


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
