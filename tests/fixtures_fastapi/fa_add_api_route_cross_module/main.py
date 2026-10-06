from fastapi import FastAPI

from handlers import list_items

app = FastAPI()
app.add_api_route("/items", list_items)