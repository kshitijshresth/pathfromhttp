from flask import Flask, request

from db import run_query
from reports import get_exporter

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me"


@app.route("/users")
def users():
    return run_query(request.args.get("q", ""))


@app.route("/export")
def export():
    return get_exporter().render()
