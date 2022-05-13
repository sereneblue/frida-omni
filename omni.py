from bottle import route, run

@route('/')
def home():
    return "Hello World!"

run(host='localhost', port=8080, debug=True)