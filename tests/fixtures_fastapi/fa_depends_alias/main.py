from fastapi import FastAPI

from deps import SessionDep

app = FastAPI()


@app.get("/items")
def items(session: SessionDep):
    return "ok"