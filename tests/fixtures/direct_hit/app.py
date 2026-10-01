from flask import Flask

app = Flask(__name__)


def vuln():
    return "boom"


@app.route("/x")
def index():
    return vuln()
