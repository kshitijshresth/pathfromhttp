from flask import Flask

app = Flask(__name__)


def vuln():
    return "boom"


def cli_only():
    return vuln()


@app.route("/x")
def index():
    return "ok"


if __name__ == "__main__":
    cli_only()
