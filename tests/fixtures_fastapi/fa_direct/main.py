from fastapi import FastAPI

app = FastAPI()


def vuln():
    return "boom"


@app.get("/x")
def index():
    return vuln()