from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from itsdangerous import URLSafeTimedSerializer
import os
import json
import re
import datetime
from datetime import timezone
import logging
import asyncio
import redis
from contextlib import asynccontextmanager
import bcrypt
from app.worker import scan_emails_task

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

# Static files & Templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Auth & Hashing ---
SECRET_KEY = os.getenv("SECRET_KEY", "a-secure-secret-key-for-sessions")
serializer = URLSafeTimedSerializer(SECRET_KEY)

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

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

def render_template(request: Request, name: str, context: dict = {}):
    """Helper to match Flask style and inject common vars"""
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
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login?error=Authentication required"}
        )
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
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    email = email.lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(password, user.password_hash):
        return RedirectResponse(url="/login?error=Invalid email or password", status_code=status.HTTP_303_SEE_OTHER)
    
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
    data: dict,
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    # data can contain email (or email_address), password, imap (or imap_server), provider
    email = data.get('email') or data.get('email_address')
    provider = data.get('provider')
    
    if not email or not provider:
        return JSONResponse({"error": "Missing email or provider"}, status_code=400)
    
    email = email.lower()
    
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
        imap_server=data.get('imap') or data.get('imap_server') if provider == 'other' else None
    )
    if provider == 'other':
        new_acc.set_credentials({"password": data.get('password')})
    
    db.add(new_acc)
    await db.commit()
    return {"status": "OK"}

@app.patch("/api/accounts")
async def update_account(
    data: dict,
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    email = data.get('email').lower()
    stmt = select(LinkedAccount).where(LinkedAccount.user_id == user.id, LinkedAccount.email_address == email)
    result = await db.execute(stmt)
    account = result.scalar_one_or_none()
    if not account:
        return JSONResponse({"error": "Account not found"}, status_code=404)
        
    if 'password' in data and account.provider == 'other':
        account.set_credentials({"password": data.get('password')})
    if ('imap' in data or 'imap_server' in data) and account.provider == 'other':
        account.imap_server = data.get('imap') or data.get('imap_server')
        
    await db.commit()
    return {"status": "OK"}

from fastapi import Query

@app.delete("/api/accounts")
async def delete_linked_account(
    email: str = Query(...),
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    from sqlalchemy import delete
    email = email.lower()
    stmt = delete(LinkedAccount).where(LinkedAccount.user_id == user.id, LinkedAccount.email_address == email)
    await db.execute(stmt)
    await db.commit()
    return {"status": "OK"}

@app.post("/api/test_connection")
async def test_connection(data: dict, user: User = Depends(login_required)):
    provider = data.get('provider')
    email = data.get('email')
    password = data.get('password')
    imap_server = data.get('imap')
    
    try:
        client = get_email_client(provider, email, password, imap_server)
        status_code, msg = client.connect()
        try:
            client.logout()
        except:
            pass
        return {"status": status_code, "message": msg}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

@app.post("/change_password")
async def change_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    if not verify_password(current_password, user.password_hash):
        return RedirectResponse(url="/dashboard?error=Current password incorrect", status_code=status.HTTP_303_SEE_OTHER)
    
    if len(new_password) < 8:
        return RedirectResponse(url="/dashboard?error=New password too short", status_code=status.HTTP_303_SEE_OTHER)

    user.password_hash = get_password_hash(new_password)
    await db.commit()
    return RedirectResponse(url="/dashboard?success=Password updated", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete_account")
async def delete_account(
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    from sqlalchemy import delete
    await db.execute(delete(User).where(User.id == user.id))
    await db.commit()
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session")
    return response

@app.get("/api/unsubscribe_links")
async def get_unsubscribe_links(
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    # Fetch all links with email address joined
    # In SQLAlchemy 2.0 async, we use select()
    stmt = (
        select(UnsubscribeLink, LinkedAccount.email_address)
        .join(LinkedAccount, UnsubscribeLink.linked_account_id == LinkedAccount.id)
        .where(UnsubscribeLink.user_id == user.id)
    )
    result = await db.execute(stmt)
    rows = result.all()

    # Grouping Logic (Server-side)
    links_by_sender = {}
    for link, email_address in rows:
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
            "account_email": email_address
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
    data: dict,
    user: User = Depends(login_required),
    db: AsyncSession = Depends(get_db)
):
    link_href = data.get('href')
    delete_others = data.get('delete_others', False)
    
    stmt = select(UnsubscribeLink).where(UnsubscribeLink.user_id == user.id, UnsubscribeLink.unsubscribe_url == link_href)
    result = await db.execute(stmt)
    link = result.scalar_one_or_none()
    
    if not link:
        return JSONResponse({"error": "Link not found"}, status_code=404)
        
    link.unsubscribed = True
    link.unsubscribed_at = datetime.datetime.now(timezone.utc)
    
    if delete_others:
        from sqlalchemy import delete
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
    email_address: str,
    num_emails: str = None,
    since_date: str = None,
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
            num_emails = "50"

    async def generate_scan_progress():
        pubsub = redis_client.pubsub()
        channel = f"scan_progress_{user.id}_{account.id}"
        pubsub.subscribe(channel)
        
        # Trigger background task AFTER subscribing to avoid race condition
        scan_emails_task.delay(user.id, account.id, num_emails, since_date)
        
        try:
            # We listen for messages on the redis channel
            # Timeout after 5 minutes of no activity
            start_time = datetime.datetime.now()
            while (datetime.datetime.now() - start_time).total_seconds() < 300:
                message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message:
                    data = message['data'].decode('utf-8')
                    yield f"data: {data}\n\n"
                    
                    # If it's complete or error, stop
                    msg_json = json.loads(data)
                    if msg_json.get('status') == 'complete' or msg_json.get('error'):
                        break
                await asyncio.sleep(0.1)
        finally:
            pubsub.unsubscribe(channel)
            pubsub.close()

    return StreamingResponse(generate_scan_progress(), media_type="text/event-stream")

# --- Google OAuth Routes ---

@app.get("/google_login")
async def google_login(request: Request, user: User = Depends(login_required)):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly']
    )
    flow.redirect_uri = str(request.url_for('oauth2callback'))
    
    # Secure state validation
    signed_state = serializer.dumps({"user_id": user.id})
    authorization_url, _ = flow.authorization_url(
        access_type='offline', 
        include_granted_scopes='true',
        state=signed_state
    )
    return RedirectResponse(authorization_url)

@app.get("/oauth2callback")
async def oauth2callback(request: Request, code: str, state: str, db: AsyncSession = Depends(get_db)):
    try:
        payload = serializer.loads(state, max_age=900) # 15 min expiry
        user_id = payload.get("user_id")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid OAuth state payload")
    
    # Fetch user without requiring standard login_required dependency (which checks cookies)
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=400, detail="User not found for OAuth state")

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly']
    )
    flow.redirect_uri = str(request.url_for('oauth2callback'))
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

    creds_json = json.dumps({
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    })
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
    return RedirectResponse(url="/dashboard")

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session")
    return response

# Placeholder for rest of routes...
