from flask import Flask

import helpers

app = Flask(__name__)


@app.route("/x/<name>")
def index(name):
    fn = getattr(helpers, name)
    return fn()
