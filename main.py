import socket
import struct

from database import add_table
from src import helpers, decode_tcp


def decode(msg):
	str_to_return = ""
	protocole = None
	count_tcp = 0

	mac_dst = struct.unpack('!6B', msg[0:6])
	mac_dst = helpers.convert_int_list_to_exa_string(mac_dst)
	temp_str = f"Address Mac Destination: {mac_dst} - "
	str_to_return += temp_str
	# print(temp_str)

	mac_src = struct.unpack('!6B', msg[6:12])
	mac_src = helpers.convert_int_list_to_exa_string(mac_src)
	temp_str = f"Address Mac Source: {mac_src} - "
	str_to_return += temp_str
	# print(temp_str)

	ether_type = struct.unpack('!H', msg[12:14])
	ether_type = helpers.convert_int_list_to_exa_string(ether_type, 4)
	temp_str = f"ether_type: {ether_type}\n"
	str_to_return += temp_str
	# print(temp_str)

	if ether_type == "0800":
		protocole = struct.unpack('!B', msg[23:24])
		protocole = protocole[0]
		temp_str = f"Protocole: {protocole} - "
		str_to_return += temp_str
		# print(temp_str)

		ip_source = struct.unpack('!4B', msg[26:30])
		ip_source = helpers.convert_int_list_to_string(ip_source)
		temp_str = f"Ip source: {ip_source} - "
		str_to_return += temp_str
		# print(temp_str)

		ip_destination = struct.unpack('!4B', msg[30:34])
		ip_destination = helpers.convert_int_list_to_string(ip_destination)
		temp_str = f"Ip destination: {ip_destination}\n"
		str_to_return += temp_str
	# print(temp_str)

	if ether_type == "0806":
		protocole = struct.unpack('!2B', msg[16:18])
		protocole = protocole[0]
		temp_str = f"Protocole: {protocole} - "
		str_to_return += temp_str
		# print(temp_str)

		sender_hardware_address = struct.unpack('!6B', msg[23:29])
		sender_hardware_address = helpers.convert_int_list_to_exa_string(
			sender_hardware_address
		)
		temp_str = f"Sender Hardware Address: {sender_hardware_address} - "
		str_to_return += temp_str
		# print(temp_str)

		sender_internet_address = struct.unpack('!4B', msg[29:33])
		sender_internet_address = helpers.convert_int_list_to_string(
			sender_internet_address
		)
		temp_str = f"Sender Internet Address: {sender_internet_address} - "
		str_to_return += temp_str
		# print(temp_str)

		target_hardware_address = struct.unpack('!6B', msg[33:39])
		target_hardware_address = helpers.convert_int_list_to_exa_string(
			target_hardware_address
		)
		temp_str = f"Target Hardware Address: {target_hardware_address} - "
		str_to_return += temp_str
		# print(temp_str)

		target_internet_address = struct.unpack('!3B', msg[39:42])
		target_internet_address = helpers.convert_int_list_to_string(
			target_internet_address
		)
		temp_str = f"Target Internet Address: {target_internet_address}\n"
		str_to_return += temp_str
	# print(temp_str)

	if protocole == 6 or protocole == 17:
		print("Protocole == 6 || 17\n")
		port_source = None
		port_dest = None
		count_tcp = count_tcp + 1
		if ether_type == "0800":
			[port_source, port_dest] = decode_tcp.decode_tcp(msg, 34)

		if ether_type == "0806":
			[port_source, port_dest] = decode_tcp.decode_tcp(msg, 42)

		temp_str = f"Port source: {port_source} - Port source: {port_dest} -" \
				   f" Number of tcp connexions: {count_tcp}\n"
		str_to_return += temp_str
	# print(temp_str)

	print(str_to_return)
	add_table.add_table(str_to_return)

	return str_to_return


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
