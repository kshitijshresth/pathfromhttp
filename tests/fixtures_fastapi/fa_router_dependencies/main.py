from fastapi import APIRouter, Depends


def vuln():
    return "boom"


def verify():
    return vuln()


router = APIRouter(dependencies=[Depends(verify)])


@router.get("/x")
def index():
    return "ok"