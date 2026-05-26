from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.db.session import Base, engine
from app.db.models import User, Verification
from app.auth.dependencies import get_optional_user
from app.routers.auth import router as auth_router
from app.routers.verify import router as verify_router
from app.routers.verify_stream import router as verify_stream_router
from app.routers.api import router as api_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Verintel", version="2.0.0")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(auth_router)
app.include_router(verify_router)
app.include_router(verify_stream_router)
app.include_router(api_router)


@app.get("/")
async def root(request: Request, current_user=Depends(get_optional_user)):
    return templates.TemplateResponse(
        request=request,
        name="pages/home.html",
        context={"user": current_user, "active": "home"}
    )
