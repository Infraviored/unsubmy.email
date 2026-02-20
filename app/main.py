from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, Query
from typing import Optional
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from itsdangerous import URLSafeTimedSerializer
import os
import json
import re
import datetime
from datetime import timezone
import logging
import asyncio
import secrets
import redis.asyncio as redis
from werkzeug.security import check_password_hash
from contextlib import asynccontextmanager
import bcrypt
from app.worker import scan_emails_task
from app.schemas import AccountAdd, AccountUpdate, UnsubscribeBase, PasswordChange

from app.models import get_db, User, LinkedAccount, UnsubscribeLink, engine, Base
from app.email_client import get_email_client

import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Shutdown logic if needed

app = FastAPI(title="unsubmy.email", lifespan=lifespan)

@app.middleware("http")
async def https_middleware(request: Request, call_next):
    if request.headers.get("x-forwarded-proto") == "https":
        request.scope["scheme"] = "https"
    response = await call_next(request)
    return response

# Static files & Templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RedirectException(Exception):
    def __init__(self, url: str):
        self.url = url

@app.exception_handler(RedirectException)
async def redirect_exception_handler(request: Request, exc: RedirectException):
    return RedirectResponse(url=exc.url, status_code=status.HTTP_303_SEE_OTHER)

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return RedirectResponse(url="/static/favicon.png")

# --- Auth & Hashing ---
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
DEFAULT_KEY = "a-secure-secret-key-for-sessions-fallback-123"
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY or SECRET_KEY in ["a-secure-secret-key-for-sessions", "change-me-in-production"]:
    logger.warning("SECRET_KEY is not set or using insecure default. Credentials may be easily compromised!")
    SECRET_KEY = SECRET_KEY or DEFAULT_KEY

serializer = URLSafeTimedSerializer(SECRET_KEY)

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        # Try bcrypt first (new format)
        if hashed_password.startswith('$2b$') or hashed_password.startswith('$2a$'):
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        # Try werkzeug (old format)
        return check_password_hash(hashed_password, plain_password)
    except Exception:
        logger.exception("Password verification failed")
        return False

# Pre-calculated dummy hash for timing attack protection
DUMMY_HASH = get_password_hash("dummy_password")

# Mock user for Jinja (similar to Flask-Login AnonymousUser)
class AnonymousUser:
    is_authenticated = False
    is_active = False
    is_anonymous = True
    id = None

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    session_cookie = request.cookies.get("session")
    user = AnonymousUser()
    if session_cookie:
        try:
            user_id = serializer.loads(session_cookie, max_age=3600*24*7)
            result = await db.execute(select(User).where(User.id == int(user_id)))
            db_user = result.scalar_one_or_none()
            if db_user:
                user = db_user
        except Exception:
            pass
    request.scope["user"] = user
    return user

def render_template(request: Request, name: str, context: dict | None = None):
    """Helper to match Flask style and inject common vars"""
    context = context or {}
    # Simple flash message handling via query param for now
    error = request.query_params.get("error")
    success = request.query_params.get("success")
    
    def get_flashed_messages(with_categories=False):
        messages = []
        if error: messages.append(("error", error))
        if success: messages.append(("success", success))
        return messages if with_categories else [m[1] for m in messages]

    default_context = {
        "request": request,
        "get_flashed_messages": get_flashed_messages,
        "current_user": request.scope.get("user", AnonymousUser()),
        "url_for": request.url_for
    }
    return templates.TemplateResponse(name, {**default_context, **context})

async def login_required(request: Request, user: User = Depends(get_current_user)):
    if not user or not user.is_authenticated:
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=401, detail="Unauthorized")
        raise RedirectException(url="/login?error=Authentication%20required")
    return user

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(get_current_user)):
    return render_template(request, "landing.html")

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user: User = Depends(get_current_user)):
    if user.is_authenticated:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return render_template(request, "login.html")

@app.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    email = email.lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    
    user_exists = user is not None
    password_correct = verify_password(password, user.password_hash) if user_exists else verify_password(password, DUMMY_HASH)
    
    if not user_exists or not password_correct:
        return RedirectResponse(url="/login?error=Invalid%20email%20or%20password", status_code=status.HTTP_303_SEE_OTHER)
    
    # Migration: Upgrade hash if it's the old format
    if not user.password_hash.startswith('$2b$') and not user.password_hash.startswith('$2a$'):
        logger.info(f"Upgrading password hash for user {user.email}")
        user.password_hash = get_password_hash(password)
        await db.commit()
    
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    session_data = serializer.dumps(str(user.id))
    response.set_cookie(
        key="session", 
        value=session_data, 
        httponly=True, 
        max_age=3600*24*7,
        secure=True, 
        samesite="lax"
    )
    return response

@app.post("/register")
async def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    email = email.lower()
    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        return RedirectResponse(url="/login?error=Email already registered", status_code=status.HTTP_303_SEE_OTHER)
    
    if len(password) < 8:
        return RedirectResponse(url="/login?error=Password must be at least 8 characters", status_code=status.HTTP_303_SEE_OTHER)

    new_user = User(email=email, password_hash=get_password_hash(password))
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    session_data = serializer.dumps(str(new_user.id))
    response.set_cookie(
        key="session", 
        value=session_data, 
        httponly=True, 
        max_age=3600*24*7,
        secure=True, 
        samesite="lax"
    )
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(login_required)):
    return render_template(request, "dashboard.html")

# --- Account API ---

@app.get("/api/accounts")
async def get_accounts(user: User = Depends(login_required), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LinkedAccount).where(LinkedAccount.user_id == user.id))
    accounts = result.scalars().all()
    return [
        {
            "email_address": acc.email_address,
            "provider": acc.provider,
            "imap_server": acc.imap_server,
            "last_scan_date": acc.last_scan_date.isoformat() if acc.last_scan_date else None
        } for acc in accounts
    ]

@app.post("/api/accounts")
async def add_account(
    data: AccountAdd,
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    email = data.email_address.lower()
    provider = data.provider
    
    # Check if already exists for this user
    result = await db.execute(
        select(LinkedAccount).where(LinkedAccount.user_id == user.id, LinkedAccount.email_address == email)
    )
    if result.scalar_one_or_none():
        return JSONResponse({"error": "Account already linked"}, status_code=400)

    new_acc = LinkedAccount(
        user_id=user.id,
        email_address=email,
        provider=provider,
        imap_server=data.imap_server if provider == 'other' else None
    )
    if provider == 'other':
        if not data.password or not data.imap_server:
            return JSONResponse({"error": "IMAP server and password are required for custom accounts"}, status_code=400)
        new_acc.set_credentials({"password": data.password})
    
    db.add(new_acc)
    await db.commit()
    return {"status": "OK"}

@app.patch("/api/accounts")
async def update_account(
    data: AccountUpdate,
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    email = data.email_address.lower()
    stmt = select(LinkedAccount).where(LinkedAccount.user_id == user.id, LinkedAccount.email_address == email)
    result = await db.execute(stmt)
    account = result.scalar_one_or_none()
    if not account:
        return JSONResponse({"error": "Account not found"}, status_code=404)
        
    if data.password and account.provider == 'other':
        account.set_credentials({"password": data.password})
    if data.imap_server and account.provider == 'other':
        account.imap_server = data.imap_server
        
    await db.commit()
    return {"status": "OK"}
@app.delete("/api/accounts")
async def delete_linked_account(
    email: str = Query(...),
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    email = email.lower()
    # First, get the account to find its ID
    stmt = select(LinkedAccount).where(LinkedAccount.user_id == user.id, LinkedAccount.email_address == email)
    result = await db.execute(stmt)
    account = result.scalar_one_or_none()
    
    if account:
        # 1. Delete associated unsubscribe links
        del_links_stmt = delete(UnsubscribeLink).where(UnsubscribeLink.linked_account_id == account.id)
        await db.execute(del_links_stmt)
        
        # 2. Delete the account itself
        del_account_stmt = delete(LinkedAccount).where(LinkedAccount.id == account.id)
        await db.execute(del_account_stmt)
        
        await db.commit()
    return {"status": "OK"}

@app.post("/api/test_connection")
async def test_connection(data: AccountAdd, user: User = Depends(login_required)):
    provider = data.provider
    email = data.email_address
    password = data.password
    imap_server = data.imap_server
    
    try:
        client = get_email_client(provider, email, password, imap_server)
        status_code, msg = client.connect()
        try:
            client.logout()
        except Exception:
            pass
        return {"status": status_code, "message": msg}
    except Exception:
        logger.exception("Connection test failed")
        return {"status": "ERROR", "message": "Failed to connect to email server"}

@app.post("/change_password")
async def change_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    try:
        data = PasswordChange(current_password=current_password, new_password=new_password)
    except Exception as e:
        return RedirectResponse(url=f"/dashboard?error={str(e)}", status_code=status.HTTP_303_SEE_OTHER)

    if not verify_password(data.current_password, user.password_hash):
        return RedirectResponse(url="/dashboard?error=Current%20password%20incorrect", status_code=status.HTTP_303_SEE_OTHER)
    
    if len(data.new_password) < 8:
        return RedirectResponse(url="/dashboard?error=New%20password%20too%20short", status_code=status.HTTP_303_SEE_OTHER)

    user.password_hash = get_password_hash(data.new_password)
    await db.commit()
    return RedirectResponse(url="/dashboard?success=Password%20updated", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete_account")
async def delete_account(
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    await db.execute(delete(User).where(User.id == user.id))
    await db.commit()
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session")
    return response

@app.get("/api/unsubscribe_links")
async def get_unsubscribe_links(
    email_address: Optional[str] = None,
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    # Fetch links for the user, optionally filtered by account email
    stmt = (
        select(UnsubscribeLink, LinkedAccount.email_address)
        .join(LinkedAccount, UnsubscribeLink.linked_account_id == LinkedAccount.id)
        .where(UnsubscribeLink.user_id == user.id)
    )
    if email_address:
        stmt = stmt.where(LinkedAccount.email_address == email_address.lower())
        
    result = await db.execute(stmt)
    rows = result.all()

    # Grouping Logic (Server-side)
    links_by_sender = {}
    for link, acc_email in rows:
        if link.list_name not in links_by_sender:
            links_by_sender[link.list_name] = []
        links_by_sender[link.list_name].append({
            "id": link.id,
            "list_name": link.list_name,
            "unsubscribe_url": link.unsubscribe_url,
            "subject": link.subject,
            "added_at": link.added_at.isoformat(),
            "unsubscribed": link.unsubscribed,
            "unsubscribed_at": link.unsubscribed_at.isoformat() if link.unsubscribed_at else None,
            "account_email": acc_email
        })

    critical = {}
    inbox = {}
    handled = {}

    for sender, sender_links in links_by_sender.items():
        # Sort by date desc
        sender_links.sort(key=lambda x: x['added_at'], reverse=True)
        
        has_unsub = False
        latest_unsub_date = None
        
        def safely_parse_date(date_str):
            try:
                return datetime.datetime.fromisoformat(date_str)
            except (ValueError, TypeError):
                return datetime.datetime.min.replace(tzinfo=timezone.utc)

        for l in sender_links:
            if l['unsubscribed']:
                has_unsub = True
                dt = safely_parse_date(l['unsubscribed_at'])
                if not latest_unsub_date or dt > latest_unsub_date:
                    latest_unsub_date = dt
        
        if has_unsub and latest_unsub_date:
            # Check for newer active emails
            has_newer_active = any(
                not l['unsubscribed'] and safely_parse_date(l['added_at']) > latest_unsub_date
                for l in sender_links
            )
            if has_newer_active:
                critical[sender] = sender_links
            else:
                # Handled: Only return the latest unsubbed link to keep it clean
                unsubbed = [l for l in sender_links if l['unsubscribed']]
                handled[sender] = [unsubbed[0]] if unsubbed else []
        else:
            inbox[sender] = sender_links

    return {
        "critical": critical,
        "inbox": inbox,
        "handled": handled,
        "counts": {
            "critical": len(critical),
            "inbox": sum(len(v) for v in inbox.values()), # Inbox often shows email count
            "inbox_senders": len(inbox),
            "handled": len(handled)
        }
    }

@app.post("/api/unsubscribe")
async def log_unsubscribe(
    data: UnsubscribeBase,
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    link_href = data.href
    delete_others = data.delete_others
    
    stmt = select(UnsubscribeLink).where(UnsubscribeLink.user_id == user.id, UnsubscribeLink.unsubscribe_url == link_href)
    result = await db.execute(stmt)
    link = result.scalar_one_or_none()
    
    if not link:
        return JSONResponse({"error": "Link not found"}, status_code=404)
        
    link.unsubscribed = True
    link.unsubscribed_at = datetime.datetime.now(timezone.utc)
    
    if delete_others:
        d_stmt = (
            delete(UnsubscribeLink)
            .where(
                UnsubscribeLink.user_id == user.id,
                UnsubscribeLink.list_name == link.list_name,
                UnsubscribeLink.id != link.id,
                UnsubscribeLink.unsubscribed.is_(False)
            )
        )
        await db.execute(d_stmt)
        
    await db.commit()
    return {"status": "OK"}


REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.from_url(REDIS_URL)

@app.get("/scan")
async def scan(
    request: Request,
    email_address: str,
    num_emails: Optional[int] = Query(None),
    since_date: Optional[str] = Query(None),
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    email_address = email_address.lower()
    
    stmt = select(LinkedAccount).where(LinkedAccount.email_address == email_address, LinkedAccount.user_id == user.id)
    result = await db.execute(stmt)
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Default logic: if no params, use smart scan
    if not num_emails and not since_date:
        if account.last_scan_date:
            since_date = account.last_scan_date.strftime('%Y-%m-%d')
        else:
            num_emails = 1000

    async def generate_scan_progress():
        pubsub = redis_client.pubsub()
        channel = f"scan_progress_{user.id}_{account.id}"
        await pubsub.subscribe(channel)
        
        # Wait for Redis to confirm the subscription before starting the scan task
        try:
            for _ in range(10):
                msg = await pubsub.get_message(ignore_subscribe_messages=False, timeout=1.0)
                if msg and msg.get("type") == "subscribe":
                    subscribed_channel = msg.get("channel")
                    if isinstance(subscribed_channel, bytes):
                        subscribed_channel = subscribed_channel.decode("utf-8")
                    if subscribed_channel == channel:
                        break
                await asyncio.sleep(0.05)
        except Exception:
            logger.exception("Error while waiting for Redis subscription confirmation")
        
        # Trigger background task AFTER confirmed subscription to avoid race condition
        scan_emails_task.delay(user.id, account.id, num_emails, since_date)
        
        try:
            # We listen for messages on the redis channel
            # Timeout after 5 minutes of no activity
            start_time = datetime.datetime.now()
            while (datetime.datetime.now() - start_time).total_seconds() < 300:
                if await request.is_disconnected():
                    logger.info(f"Client disconnected for user {user.id}")
                    break
                    
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message:
                    data = message['data'].decode('utf-8')
                    yield f"data: {data}\n\n"
                    
                    # If it's complete or error, stop
                    msg_json = json.loads(data)
                    if msg_json.get('status') == 'complete' or msg_json.get('error'):
                        break
                await asyncio.sleep(0.1)
        except Exception:
            logger.exception("Error in scan progress generator")
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()

    return StreamingResponse(generate_scan_progress(), media_type="text/event-stream")

# --- Google OAuth Routes ---

@app.get("/login/google")
async def google_login(request: Request, user: User = Depends(login_required)):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly']
    )
    # Explicitly force HTTPS for the redirect URI
    flow.redirect_uri = str(request.url_for('oauth2callback')).replace("http://", "https://")
    
    # Step 1: Force Alphanumeric State (No periods, short length)
    state = secrets.token_hex(16)
    
    authorization_url, _ = flow.authorization_url(
        access_type='offline', 
        include_granted_scopes='true',
        prompt='consent',
        state=state
    )
    
    response = RedirectResponse(authorization_url)
    # Step 2: The Parallel State Cookie (Hard-coded Secure)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        max_age=900,
        secure=True,
        samesite="lax"
    )
    return response

@app.get("/oauth2callback")
async def oauth2callback(request: Request, code: str, state: str, user: User = Depends(login_required), db: AsyncSession = Depends(get_db)):
    # Validate state against cookie
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly']
    )
    # Explicitly force HTTPS for the redirect URI
    flow.redirect_uri = str(request.url_for('oauth2callback')).replace("http://", "https://")
    flow.fetch_token(code=code)
    
    credentials = flow.credentials
    # Get user email from Gmail API
    service = build('gmail', 'v1', credentials=credentials)
    profile = service.users().getProfile(userId='me').execute()
    email = profile['emailAddress'].lower()

    # Create/Update account
    stmt = select(LinkedAccount).where(LinkedAccount.user_id == user.id, LinkedAccount.email_address == email)
    result = await db.execute(stmt)
    account = result.scalar_one_or_none()

    if not account:
        account = LinkedAccount(
            user_id=user.id,
            email_address=email,
            provider='gmail',
        )
        # Store OAuth token (encrypt it)
        account.set_credentials(json.loads(google.oauth2.credentials.Credentials.to_json(credentials)))
        db.add(account)
    else:
        # Store OAuth token (encrypt it)
        account.set_credentials(json.loads(google.oauth2.credentials.Credentials.to_json(credentials)))
    
    await db.commit()
    
    # After successful OAuth, ensure a session exists for the user
    session_data = serializer.dumps(str(user.id))
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="session", 
        value=session_data, 
        httponly=True, 
        max_age=3600*24*7,
        secure=True, 
        samesite="lax"
    )
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session")
    return response

# Placeholder for rest of routes...
