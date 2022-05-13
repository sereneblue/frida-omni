from bottle import Bottle, get, post, run

app = Bottle()

@app.get('/')
def home():
    return ""

@app.get('/api/devices')
def devices():
    return ""

@app.get('/api/applications/<device_id>')
def get_applications(device_id=""):
    return ""

@app.get('/api/log/<log_type>')
def get_logs(log_type=""):
    return ""

@app.post('/api/action/<device_id>')
def app_action(device_id=""):
    return ""

run(app, host='localhost', port=8080, debug=False)