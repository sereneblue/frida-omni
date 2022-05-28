from bottle import Bottle, get, post, request, response, run, static_file
from time import sleep
import bottle
import base64
import frida
import glob
import operator
import struct
import sqlite3
import tempfile

import omni_log

CURRENT_DEVICE = ""
CURRENT_APP = ""
SESSION = None
SCRIPTS = {}

app = Bottle()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row
cur = db.cursor()

@app.route('/', method = 'OPTIONS')
@app.route('/<path:path>', method = 'OPTIONS')
def options_handler(path = None):
    return

@app.get('/api/devices')
def devices():
    device_list = []
    devices = frida.get_device_manager().enumerate_devices()

    for device in devices:
        if device.type == 'usb':
            device_list.append({
                'name': device.name,
                'id': device.id   
            })

    return dict(data=device_list, success=True)

@app.get('/api/applications/<device_id>')
def get_applications(device_id=""):
    application_list = []

    device = None

    try:
        device = frida.get_device_manager().get_device_matching(lambda d: d.id == device_id, timeout = 1)
    except frida.InvalidArgumentError:
        pass

    if not device:
        return dict(data=application_list, success=False, message="Unable to find device")

    apps = device.enumerate_applications(scope = "full")

    for app in apps:
        application_list.append({
            'name': app.name,
            'id': app.identifier,
            'icon': get_icon(app.parameters)
        })

    application_list.sort(key = operator.itemgetter('name'))

    return dict(data=application_list, success=True, message="")

@app.post('/api/logs')
def get_logs():
    totals = {}
    logs = {}
    meta = {}

    device_id = request.json['deviceId']
    app_id = request.json['appId']

    # check if device and app exist
    device = None

    try:
        device = frida.get_device_manager().get_device_matching(lambda d: d.id == device_id)
    except frida.InvalidArgumentError:
        pass

    if not device:
        return dict(data={"logs": logs, "totals": totals, "meta": meta}, success=False, message="device_not_found")

    apps = device.enumerate_applications()
    application_list = [app for app in apps if app.identifier == app_id]

    if len(application_list) == 0:
        return dict(data={"logs": logs, "totals": totals, "meta": meta}, success=False, message="app_not_found")

    meta['name'] = application_list[0].name

    # check if requested app log is loaded
    if not ((CURRENT_APP == "" and CURRENT_DEVICE == "") or (CURRENT_APP == app_id and CURRENT_DEVICE == device_id)):
        clear_session()
        reset_db()

    meta['running'] = is_running(device, app_id)

    for log in request.json['logs']:
        log_data = []

        if log == 'crypto':
            search_text = request.json['queryData']['search'].get(log)
            params = []

            base_query_string = "select * from log_crypto "

            if search_text:
                base_query_string += " where params like ? "
                params.append('%' + search_text + '%')

            base_query_string += " order by id desc limit 100;"

            cur.execute(base_query_string, tuple(params))
            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'method': row['method'],
                    'params': row['params']
                })
        elif log == 'fs':
            search_text = request.json['queryData']['search'].get(log)
            params = []

            base_query_string = "select * from log_fs "

            if search_text:
                base_query_string += " where path like ? "
                params.append('%' + search_text + '%')

            base_query_string += " order by id desc limit 100;"

            cur.execute(base_query_string, tuple(params))

            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'path': row['path']
                })
        elif log == 'hash':
            search_text = request.json['queryData']['search'].get(log)
            params = []

            base_query_string = "select * from log_hash "

            if search_text:
                base_query_string += " where input like ? or output like ?"
                params.append('%' + search_text + '%')
                params.append('%' + search_text + '%')

            base_query_string += " order by id desc limit 100;"

            cur.execute(base_query_string, tuple(params))
            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'algo': row['algo'],
                    'timestamp': row['timestamp'],
                    'input': row['input'],
                    'output': row['output']
                })
        elif log == 'http':
            search_text = request.json['queryData']['search'].get(log)
            params = []

            base_query_string = "select * from log_http "

            if search_text:
                base_query_string += " where url like ? "
                params.append('%' + search_text + '%')

            base_query_string += " order by id desc limit 100;"

            cur.execute(base_query_string, tuple(params))

            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'url': row['url']
                })
        elif log == 'pkg_info':
            log_data = {}

            cur.execute("select * from log_pkg_info")
            for row in cur:
                if row['type'] == 'metadata':
                    log_data[row['name']] = row['value']
                else:
                    if log_data.get(row['type']) == None:
                        log_data[row['type']] = []

                    log_data[row['type']].append({
                        'name': row['name'],
                        'value': row['value']
                        })
        elif log == 'shared_prefs':
            cur.execute("select * from log_shared_prefs order by id desc limit 100")
            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'method': row['method'],
                    'value': row['value']
                })
        elif log == 'sqlite':
            search_text = request.json['queryData']['search'].get(log)
            params = []

            base_query_string = "select * from log_sqlite "

            if search_text:
                base_query_string += " where value like ? "
                params.append('%' + search_text + '%')

            base_query_string += " order by id desc limit 100;"

            cur.execute(base_query_string, tuple(params))

            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'method': row['method'],
                    'value': row['value']
                })

        logs[log] = log_data

        if type(log_data) == list and len(log_data) > 0:
            totals[log] = log_data[0]['id']
        else:
            totals[log] = 0

    return dict(data={"logs": logs, "totals": totals, "meta": meta}, success=True, message="")

@app.post('/api/action')
def app_action():
    global CURRENT_DEVICE, CURRENT_APP, SESSION

    device_id = request.forms.get("deviceId")
    app_id = request.forms.get("appId")
    action = request.forms.get("action")

    device = None
    data = None

    try:
        device = frida.get_device_manager().get_device_matching(lambda d: d.id == device_id, timeout = 1)
    except frida.InvalidArgumentError:
        pass

    if not device:
        return dict(data=None, success=False, message="Unable to find device")

    if action == 'start':
        clear_session()

        pid = device.spawn(app_id)
        SESSION = device.attach(pid)
        create_scripts()
        device.resume(pid)
        load_scripts()

        CURRENT_DEVICE = device_id
        CURRENT_APP = app_id
    elif action == 'stop':
        clear_session()
        stop_app(device, app_id)
    elif action == 'download':
        with tempfile.NamedTemporaryFile() as tmp_db:
            tmp_db_con = sqlite3.connect(tmp_db.name)
            db.commit()
            db.backup(tmp_db_con)
            data = base64.b64encode(tmp_db.read()).decode('utf-8')

    return dict(data=data, success=True, message="")

@app.get('/<path:path>')
def home(path):
    return static_file(path, root='./build')

@app.get('/')
@app.get('/applications')
@app.get('/dashboard')
def home():
    return static_file('index.html', root='build/')

@app.hook('after_request')
def enable_cors():
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'PUT, GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Origin, Accept, Content-Type, X-Requested-With'

def create_db():
    cur.executescript("""
        create table log_crypto (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
            method TEXT NOT NULL,
            params TEXT NOT NULL
        );

        create index log_crypto_idx on log_crypto (method);

        create table log_fs (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
            path TEXT NOT NULL
        );

        create table log_hash (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
            algo TEXT NOT NULL,
            input TEXT NOT NULL,
            output TEXT NOT NULL
        );

        create index log_hash_idx on log_hash (algo);

        create table log_http (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
            url TEXT NOT NULL
        );

        create table log_pkg_info (
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL
        );

        create index log_pkg_info_idx on log_pkg_info (type);

        create table log_shared_prefs (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
            method TEXT NOT NULL,
            value TEXT NOT NULL
        );

        create index log_shared_prefs_idx on log_shared_prefs (method);

        create table log_sqlite (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
            method TEXT NOT NULL,
            db TEXT NOT NULL,
            value TEXT NOT NULL
        );

        create index log_sqlite_idx on log_sqlite (method);
    """)

def get_icon(app_params):
    icons = app_params['icons'][0] if app_params.get('icons') else None

    if icons:
        if icons['format'] == 'png':
            return "data:image/png;base64," + base64.b64encode(icons['image']).decode('utf-8')

    return None

def reset_db():
    global db, cur

    db.close()

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    cur = db.cursor()

    create_db()

def clear_session():
    global SESSION

    if SESSION:
        SESSION.detach()

    SESSION = None

def create_scripts():
    global SCRIPTS, SESSION

    for script in glob.glob('hooks/*.js'):
        script_name = script.replace('.js', '').replace('hooks/', '')

        with open(script, 'r') as script_file: 
            SCRIPTS[script_name] = SESSION.create_script(script_file.read())
            SCRIPTS[script_name].on('message', on_message)
            sleep(.5)

def stop_app(device, app_id):
    apps = device.enumerate_applications()
    apps = [app for app in apps if app.identifier == app_id]

    if len(apps) > 0:
        for p in device.enumerate_processes():
            if p.name == apps[0].name:
                device.kill(p.pid)

def is_running(device, app_id):
    global SESSION

    apps = device.enumerate_applications()
    apps = [app for app in apps if app.identifier == app_id]

    if len(apps) > 0:
        for p in device.enumerate_processes():
            if p.name == apps[0].name:
                return True and SESSION and not SESSION.is_detached

    return False

def load_scripts():
    global SCRIPTS

    for script in SCRIPTS:
        SCRIPTS[script].load()

def on_message(message, data):
    log_func = {
        'crypto': omni_log.log_crypto,
        'fs': omni_log.log_fs,
        'hash': omni_log.log_hash,
        'http': omni_log.log_http,
        'pkg_info': omni_log.log_pkg_info,
        'shared_prefs': omni_log.log_shared_prefs,
        'sqlite': omni_log.log_sqlite
    }

    if message['type'] == 'send':
        log_func[message['payload']['log']](cur, message['payload'])
    else:
        print(message)

create_db()
run(app, host='localhost', port=8080, debug=False)