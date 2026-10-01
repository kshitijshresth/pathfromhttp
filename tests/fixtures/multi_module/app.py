from flask import Flask

from helpers import process

app = Flask(__name__)


@app.route("/x")
def index():
    return process()
