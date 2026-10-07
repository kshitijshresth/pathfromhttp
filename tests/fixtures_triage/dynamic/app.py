from flask import Flask

import handlers

app = Flask(__name__)


@app.route("/run/<name>")
def run(name):
    fn = getattr(handlers, name)
    return fn()
