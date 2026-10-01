from flask import Flask

app = Flask(__name__)


def vuln():
    return "boom"


def step_b():
    return vuln()


def step_a():
    return step_b()


@app.route("/x", methods=["POST"])
def upload():
    return step_a()
