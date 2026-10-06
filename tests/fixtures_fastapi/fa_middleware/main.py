from fastapi import FastAPI, Request

app = FastAPI()


def audit():
    return "boom"


@app.middleware("http")
async def mw(request: Request, call_next):
    audit()
    return await call_next(request)