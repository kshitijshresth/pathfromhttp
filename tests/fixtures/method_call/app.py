from flask import Flask

app = Flask(__name__)


def vuln():
    return "boom"


class Service:
    def run(self):
        return self.inner()

    def inner(self):
        return vuln()


@app.route("/x")
def index():
    svc = Service()
    return svc.run()
