from bottle import Bottle, get, post, run
import base64
import frida
import operator
import struct

app = Bottle()

@app.get('/')
def home():
    return ""

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

@app.get('/api/log/<log_type>')
def get_logs(log_type=""):
    return ""

@app.post('/api/action/<device_id>')
def app_action(device_id=""):
    return ""

def get_icon(app_params):
    icons = app_params['icons'][0] if app_params.get('icons') else None

    if icons:
        if icons['format'] == 'png':
            return "data:image/png;base64," + base64.b64encode(icons['image']).decode('utf-8')

    return None

run(app, host='localhost', port=8080, debug=True)