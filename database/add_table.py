import psycopg2

from database import db_config


def add_table(log):
	""" Connect to the PostgreSQL database server """
	global cur
	conn = None
	try:
		# read connection parameters
		params = db_config.db_config()
		# connect to the PostgreSQL server
		print('Connecting to the PostgreSQL database...')
		conn = psycopg2.connect(**params)
		# create a cursor
		cur = conn.cursor()
		# execute a statement
		print('PostgreSQL database version:')
		cur.execute('SELECT version()')
		# display the PostgreSQL database server version
		db_version = cur.fetchone()
		print(db_version)
		# close the communication with the PostgreSQL
		cur.close()

		print("Table Before updating record ")
		sql_select_query = """INSERT INTO logs(LOG) VALUES %s"""
		cur.execute(sql_select_query, (log,))
		conn.commit()

	except (Exception, psycopg2.Error) as error:
		print(error)
	finally:
		if conn is not None:
			cur.close()
			conn.close()
			print('PostgreSQL connection closed.')
