import os
import json
import datetime
from datetime import timezone
import logging
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, Response, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from app.email_client import get_email_client
from app.models import db, User, LinkedAccount, UnsubscribeLink
from werkzeug.middleware.proxy_fix import ProxyFix

# --- Google OAuth Imports ---
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.auth.transport.requests

# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "a-very-secure-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PREFERRED_URL_SCHEME'] = 'https'

# --- FIX for Reverse Proxy ---
# Tell the app that it's behind a proxy and to trust the X-Forwarded-Proto header.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Initialization ---
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper Functions ---
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

# --- Main Routes (Landing, Auth, Dashboard) ---
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first() # type: ignore
        if user is None or not user.check_password(password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    email = request.form.get('email').lower()
    password = request.form.get('password')
    
    if User.query.filter_by(email=email).first():
        flash('Email address already registered.', 'error')
        return redirect(url_for('login'))
        
    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Changes the current user's password."""
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    if not current_user.check_password(current_password):
        flash('Your current password was incorrect.', 'error')
        return redirect(url_for('dashboard'))
    
    if len(new_password) < 8:
        flash('Your new password must be at least 8 characters long.', 'error')
        return redirect(url_for('dashboard'))

    current_user.set_password(new_password)
    db.session.commit()
    
    flash('Your password has been changed successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    """Deletes the user's account and all associated data."""
    try:
        user_id = current_user.id
        user = User.query.get(user_id)
        if user:
            # The cascade delete on the model will handle linked accounts
            db.session.delete(user)
            db.session.commit()
            logout_user()
            flash('Your account has been successfully deleted.', 'success')
            return redirect(url_for('index'))
        else:
            flash('User not found.', 'error')
            return redirect(url_for('dashboard'))
    except Exception as e:
        logging.error(f"Error deleting account for user {current_user.email}: {e}")
        db.session.rollback()
        flash('An error occurred while deleting your account. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# --- Google OAuth Routes ---
@app.route('/login/google')
@login_required
def google_login():
    # Relax strict HTTPS check for oauthlib running inside container (SSL terminated at Nginx)
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" 
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')
    logging.info(f"Using OAuth Redirect URI: {redirect_uri}")

    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=['https://www.googleapis.com/auth/gmail.readonly'],
        redirect_uri=redirect_uri)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
@login_required
def oauth2callback():
    state = session['state']
    redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')
    
    flow = Flow.from_client_secrets_file(
        'client_secret.json', scopes=['https://www.googleapis.com/auth/gmail.readonly'],
        state=state, redirect_uri=redirect_uri)

    # Force HTTPS for the authorization response URL if it comes in as HTTP
    auth_response_url = request.url
    if auth_response_url.startswith('http:'):
        auth_response_url = auth_response_url.replace('http:', 'https:', 1)

    logging.warning(f"Request URL from Google (forced HTTPS): {auth_response_url}")
    
    flow.fetch_token(authorization_response=auth_response_url)
    credentials = flow.credentials

    logging.warning("--- Google OAuth Callback Data ---")
    logging.warning(f"Token: {credentials.token}")
    logging.warning(f"Refresh Token: {credentials.refresh_token}")
    logging.warning(f"Scopes: {credentials.scopes}")
    
    cred_dict = credentials_to_dict(credentials)
    logging.warning(f"Credentials dictionary to be stored: {json.dumps(cred_dict)}")

    service = build('gmail', 'v1', credentials=credentials)
    profile = service.users().getProfile(userId='me').execute()
    email_address = profile['emailAddress'].lower()

    # Check if this email is already linked
    existing_account = LinkedAccount.query.filter_by(email_address=email_address, user_id=current_user.id).first() # type: ignore
    if existing_account:
        # Update credentials
        existing_account.credentials = json.dumps(cred_dict)
    else:
        # Create new linked account
        new_account = LinkedAccount(
            user_id=current_user.id, # type: ignore
            email_address=email_address, # type: ignore
            provider="gmail", # type: ignore
            credentials=json.dumps(cred_dict) # type: ignore
        )
        db.session.add(new_account)
    
    db.session.commit()
    return redirect(url_for('dashboard'))

# --- API Endpoints for Account Management ---
@app.route('/api/accounts', methods=['GET'])
@login_required
def get_accounts():
    accounts = LinkedAccount.query.filter_by(user_id=current_user.id).all()
    # The frontend expects a list of objects, not a dictionary.
    safe_accounts = [
        {
            "email_address": acc.email_address, 
            "provider": acc.provider, 
            "imap_server": acc.imap_server
        } for acc in accounts
    ]
    return jsonify(safe_accounts)

@app.route('/api/accounts', methods=['POST'])
@login_required
def add_account():
    data = request.get_json() or {}
    email = data.get('email_address').lower()
    if not email:
        return jsonify({"status": "ERROR", "message": "Email address is required."}), 400
    
    new_account = LinkedAccount(
        user_id=current_user.id, # type: ignore
        email_address=email, # type: ignore
        provider=data.get("provider"), # type: ignore
        imap_server=data.get("imap_server"), # type: ignore
        credentials=json.dumps({"password": data.get("password")}) # Encrypt this in a real app
    )
    db.session.add(new_account)
    db.session.commit()
    return jsonify({"status": "OK", "message": f"Account {email} saved."})

@app.route('/api/accounts/update', methods=['POST'])
@login_required
def update_account():
    data = request.get_json() or {}
    email = data.get('email_address').lower()
    account = LinkedAccount.query.filter_by(email_address=email, user_id=current_user.id).first_or_404() # type: ignore
    
    # Update password if provided
    if data.get('password'):
        # In a real app, you'd merge the JSON, not overwrite it.
        # But for now, we only store the password for IMAP.
        account.credentials = json.dumps({"password": data.get("password")})

    # Update IMAP server if provided (for 'other' provider)
    if data.get('imap_server') is not None:
        account.imap_server = data.get('imap_server')
    
    db.session.commit()
    return jsonify({"status": "OK", "message": f"Account {email} updated."})

@app.route('/api/accounts/delete', methods=['POST'])
@login_required
def delete_linked_account():
    data = request.get_json() or {}
    email = data.get('email_address').lower()
    account = LinkedAccount.query.filter_by(email_address=email, user_id=current_user.id).first_or_404() # type: ignore
    db.session.delete(account)
    db.session.commit()
    return jsonify({"status": "OK", "message": f"Account {email} deleted."})

@app.route('/api/test_connection', methods=['POST'])
@login_required
def test_connection():
    data = request.get_json() or {}
    try:
        client = get_email_client(
            data['provider'], data['email_address'].lower(), data.get('password'), data.get('imap_server')
        )
        client.connect()
        client.logout()
        return jsonify({"status": "OK", "message": "Connection successful!"})
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# --- API Endpoints for Scanning & Results ---
@app.route('/api/unsubscribe_links', methods=['GET'])
@login_required
def get_unsubscribe_links():
    links = db.session.query(UnsubscribeLink, LinkedAccount.email_address).join(LinkedAccount, UnsubscribeLink.linked_account_id == LinkedAccount.id).filter(UnsubscribeLink.user_id == current_user.id).order_by(UnsubscribeLink.unsubscribed.asc(), UnsubscribeLink.added_at.desc()).all()
    
    links_data = []
    for link, email_address in links:
        links_data.append({
            "id": link.id,
            "email_address": email_address,
            "list_name": link.list_name,
            "unsubscribe_url": link.unsubscribe_url,
            "added_at": link.added_at.isoformat(),
            "unsubscribed": link.unsubscribed,
            "unsubscribed_at": link.unsubscribed_at.isoformat() if link.unsubscribed_at else None,
            "subject": link.subject,
            "link_text": link.link_text
        })
    return jsonify(links_data)

@app.route('/api/unsubscribe', methods=['POST'])
@login_required
def log_unsubscribe():
    """Marks a specific unsubscribe link as actioned."""
    data = request.json
    link_href = data.get('href')
    if not link_href:
        return jsonify({"status": "ERROR", "message": "Link href is required."}), 400

    link = UnsubscribeLink.query.filter_by(user_id=current_user.id, unsubscribe_url=link_href).first()

    if not link:
        return jsonify({"status": "ERROR", "message": "Link not found."}), 404
        
    link.unsubscribed = True
    link.unsubscribed_at = datetime.datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"status": "OK"})

@app.route('/scan')
@login_required
def scan():
    email_address = request.args.get('email_address').lower()
    num_emails_str = request.args.get('num_emails')
    since_date_str = request.args.get('since_date')
    user_id = current_user.id # Get user_id while request context is active
    
    account = LinkedAccount.query.filter_by(email_address=email_address, user_id=user_id).first_or_404() # type: ignore

    def generate_scan_progress(scan_user_id):
        with app.app_context():
            try:
                creds_dict = json.loads(account.credentials) if account.credentials else {}
                
                if account.provider == 'gmail':
                    password_or_creds = creds_dict
                else:
                    password_or_creds = creds_dict.get('password')

                client = get_email_client(
                    account.provider, 
                    account.email_address, 
                    password_or_creds, 
                    account.imap_server
                )
                status, msg = client.connect()
                if status == "ERROR":
                    logging.error(f"Scan connection failed for {account.email_address}: {msg}")
                    yield f'data: {json.dumps({"error": f"Connection failed: {msg}"})}\n\n'
                    return
                else:
                    logging.info(f"Scan connection successful for {account.email_address}")

                scan_params = {}
                if num_emails_str:
                    scan_params['num_emails'] = int(num_emails_str)
                if since_date_str:
                    scan_params['since_date'] = since_date_str
                
                for progress_update in client.scan_emails(**scan_params):
                    if not isinstance(progress_update, dict):
                        logging.warning(f"Received non-dict progress update: {progress_update}")
                        continue

                    if 'links' in progress_update: # Final summary update from scanner
                        new_links_payload = progress_update.get('links', {})
                        new_links_found = 0

                        # Get all existing URLs for the user to prevent duplicates efficiently
                        existing_urls = {link.unsubscribe_url for link in UnsubscribeLink.query.filter_by(user_id=scan_user_id).all()}

                        for domain, links_list in new_links_payload.items():
                            for link_info in links_list:
                                url = link_info['href']
                                if url not in existing_urls:
                                    new_link = UnsubscribeLink(
                                        user_id=scan_user_id,
                                        linked_account_id=account.id,
                                        list_name=link_info.get('from', domain),
                                        unsubscribe_url=url,
                                        subject=link_info.get('subject'),
                                        link_text=link_info.get('text'),
                                        added_at=datetime.datetime.fromisoformat(link_info['date']) if link_info.get('date') else datetime.datetime.now(timezone.utc)
                                    )
                                    db.session.add(new_link)
                                    existing_urls.add(url) # Add to set to handle duplicates within same scan
                                    new_links_found += 1
                        
                        if new_links_found > 0:
                            db.session.commit()
                        
                        all_user_links = db.session.query(UnsubscribeLink, LinkedAccount.email_address).join(LinkedAccount, UnsubscribeLink.linked_account_id == LinkedAccount.id).filter(UnsubscribeLink.user_id == scan_user_id).order_by(UnsubscribeLink.unsubscribed.asc(), UnsubscribeLink.added_at.desc()).all()
                        
                        final_data = {
                            "status": "completed",
                            "description": progress_update.get("description", f"Scan complete."),
                             "date_range": progress_update.get("date_range"),
                            "new_links_found": new_links_found,
                            "links": [
                                {
                                    "id": l.id,
                                    "email_address": email,
                                    "list_name": l.list_name, 
                                    "unsubscribe_url": l.unsubscribe_url,
                                    "added_at": l.added_at.isoformat(),
                                    "unsubscribed": l.unsubscribed,
                                    "unsubscribed_at": l.unsubscribed_at.isoformat() if l.unsubscribed_at else None,
                                    "subject": l.subject,
                                    "link_text": l.link_text
                                } for l, email in all_user_links
                            ]
                        }
                        yield f"data: {json.dumps(final_data)}\n\n"
                    else:
                        # It's a progress update, just forward it
                        yield f"data: {json.dumps(progress_update)}\n\n"
                
                client.logout()

            except Exception as e:
                logging.error(f"Error during scan for {email_address}: {e}", exc_info=True)
                yield f'data: {json.dumps({"error": str(e)})}\n\n'

    return Response(generate_scan_progress(user_id), mimetype='text/event-stream')

def run():
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=5001)
