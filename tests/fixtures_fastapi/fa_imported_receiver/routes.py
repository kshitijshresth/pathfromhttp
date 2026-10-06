from main import app
from util import vuln


@app.get("/x")
def index():
    return vuln()