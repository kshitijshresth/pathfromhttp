from fastapi import FastAPI

app = FastAPI()


def vuln():
    return "boom"


def seed():
    return vuln()


@app.on_event("startup")
def on_start():
    return seed()


@app.get("/x")
def index():
    return "ok"