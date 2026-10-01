from flask import Blueprint, Flask

bp = Blueprint("bp", __name__)
app = Flask(__name__)


def vuln():
    return "boom"


@bp.route("/y")
def handler():
    return vuln()


app.register_blueprint(bp)
