from fastapi import Depends, FastAPI

app = FastAPI()


def clamp(n):
    return "boom"


class Pagination:
    def __init__(self, limit: int = 10):
        self.limit = clamp(limit)


@app.get("/items")
def items(p: Pagination = Depends(Pagination)):
    return "ok"