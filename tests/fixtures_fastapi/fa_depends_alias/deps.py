from typing import Annotated

from fastapi import Depends


def open_session():
    return "boom"


def get_db():
    return open_session()


SessionDep = Annotated[object, Depends(get_db)]