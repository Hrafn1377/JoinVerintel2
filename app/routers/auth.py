from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User
from app.auth.security import hash_password, verify_password, create_access_token
from app.auth.dependencies import get_optional_user

templates = Jinja2Templates(directory="templates")

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/register")
async def register_page(
    request: Request,
    current_user=Depends(get_optional_user)
):
    if current_user:
        return RedirectResponse(url="/")
    return templates.TemplateResponse(
        request=request,
        name="pages/auth/register.html",
        context={"user": None, "active": ""}
    )


@router.post("/register")
async def register_submit(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
):
    existing = db.query(User).filter(User.email == email.lower().strip()).first()
    if existing:
        return templates.TemplateResponse(
            request=request,
            name="pages/auth/register.html",
            context={
                "user": None,
                "active": "",
                "error": "An account with that email already exists."
            }
        )

    user = User(
        email=email.lower().strip(),
        hashed_password=hash_password(password),
    )
    db.add(user)
    db.commit()

    token = create_access_token({"sub": user.id})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=60 * 60 * 24 * 7,
        samesite="lax"
    )
    return response


@router.get("/login")
async def login_page(
    request: Request,
    current_user=Depends(get_optional_user)
):
    if current_user:
        return RedirectResponse(url="/")
    return templates.TemplateResponse(
        request=request,
        name="pages/auth/login.html",
        context={"user": None, "active": ""}
    )


@router.post("/login")
async def login_submit(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
):
    user = db.query(User).filter(User.email == email.lower().strip()).first()

    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request=request,
            name="pages/auth/login.html",
            context={
                "user": None,
                "active": "",
                "error": "Invalid email or password."
            }
        )

    token = create_access_token({"sub": user.id})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=60 * 60 * 24 * 7,
        samesite="lax"
    )
    return response


@router.post("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    return response
