from fastapi import APIRouter

from util import vuln

router = APIRouter()


@router.post("/items")
async def create_item():
    return vuln()