def convert_int_list_to_exa_string(list_int, size=2, separator=":"):
	"""
	Convert int list to exa string, with a define separator
	Args:
		list_int: A list with int  (34, 60, 174, 125, 113, 100)
		size: Size of the hexadecimal
		separator: The separator wanted
	Return:
		A string with hexadecimal - Ex: [65, 66, 67, 66]
	"""

	return f"{separator}".join(
		[hex(part)[2:].zfill(size) for part in list_int]
	)


def convert_int_list_to_string(list_int, separator="."):
	"""
	Convert int list to a string, with a define separator
	Args:
		list_int: A list with int  (34, 60, 174, 125, 113, 100)
		separator: The separator wanted
	Return:
		A string with hexadecimal - Ex: [65, 66, 67, 66]
	"""
	return f"{separator}".join(str(part) for part in list_int)
