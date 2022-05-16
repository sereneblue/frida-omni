from bottle import Bottle, get, post, request, response, run 
import bottle
import base64
import frida
import operator
import struct
import sqlite3

import omni_log

app = Bottle()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row
cur = db.cursor()

@app.get('/')
def home():
    return ""

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
        device = frida.get_device_manager().get_device_matching(lambda d: d.id == device_id)
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

    for log in request.json['logs']:
        log_data = []

        if log == 'hash':
            cur.execute("select * from log_hash order by id desc limit 100;")
            
            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'algo': row['algo'],
                    'timestamp': row['timestamp'],
                    'input': row['input'],
                    'output': row['output']
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
        elif log == 'sqlite':
            cur.execute("select * from log_sqlite order by id desc limit 100")
            for row in cur:
                log_data.append({
                    'id': row['id'],
                    'method': row['method'],
                    'db': row['db'],
                    'value': row['value']
                })
        else:
            pass

        logs[log] = log_data

        if type(log_data) == list and len(log_data) > 0:
            totals[log] = log_data[0]['id']
        else:
            totals[log] = 0

    return dict(data={"logs": logs, "totals": totals}, success=True, message="")

@app.post('/api/action/<device_id>')
def app_action(device_id=""):
    return ""

@app.hook('after_request')
def enable_cors():
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'PUT, GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Origin, Accept, Content-Type, X-Requested-With'

def create_db():
    cur.executescript("""
        create table log_pkg_info (
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL
        );

        create index log_pkg_info_idx on log_pkg_info (type);

        create table log_sqlite (
            id INTEGER PRIMARY KEY,
            method TEXT NOT NULL,
            db TEXT NOT NULL,
            value TEXT NOT NULL
        );

        create index log_sqlite_idex on log_sqlite (method);

        create table log_hash (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            algo TEXT NOT NULL,
            input TEXT NOT NULL,
            output TEXT NOT NULL
        );

        create index log_hash_idx on log_hash (algo);
    """)

def get_icon(app_params):
    icons = app_params['icons'][0] if app_params.get('icons') else None

    if icons:
        if icons['format'] == 'png':
            return "data:image/png;base64," + base64.b64encode(icons['image']).decode('utf-8')

    return None

def on_message(message, data):
    log_func = {
        'hash': omni_log.log_hash,
        'pkg_info': omni_log.log_pkg_info,
        'sqlite': omni_log.log_sqlite
    }

    if message['type'] == 'send':
        log_func[message['payload']['log']](cur, message['payload'])
    else:
        print(message)

create_db()
run(app, host='localhost', port=8080, debug=True)