from fastapi import Depends, FastAPI

from auth import get_current_user

app = FastAPI()


@app.get("/me")
def me(user=Depends(get_current_user)):
    return user