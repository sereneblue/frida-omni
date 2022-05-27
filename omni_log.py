def log_crypto(cur, payload):
	cur.execute("""
		insert into log_crypto(method, params) values (?, ?);
	""", (payload['method'], payload['params']))

def log_fs(cur, payload):
	cur.execute("""
		insert into log_fs(path) values (?);
	""", (payload['path'],))

def log_hash(cur, payload):
	cur.execute("""
		insert into log_hash(algo, input, output) values (?, ?, ?);
	""", (payload['algo'], payload['input'], payload['output']))

def log_http(cur, payload):
	cur.execute("""
		insert into log_http(url) values (?);
	""", (payload['url'],))

def log_pkg_info(cur, payload):
	rows = []

	rows.append(('metadata', 'id', payload['id']))
	rows.append(('metadata', 'name', payload['name']))
	rows.append(('metadata', 'version', payload['version']))

	package_info = ['activities', 'permissions', 'providers', 'receivers', 'services', 'sharedLibs']
	for p in package_info:
		for val in payload[p]:
			rows.append((p, val['name'], val['value']))

	cur.executemany("""
		insert into log_pkg_info(type, name, value) values (?, ?, ?);
	""", rows)

def log_shared_prefs(cur, payload):
	cur.execute("""
		insert into log_shared_prefs(method, value) values (?, ?);
	""", (payload['method'], payload['value']))

def log_sqlite(cur, payload):
	cur.execute("""
		insert into log_sqlite(method, db, value) values (?, ?, ?);
	""", (payload['method'], payload['db'], payload['value']))