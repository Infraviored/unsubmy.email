import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
from tqdm import tqdm
from app.link_finder import find_unsubscribe_links
from config import DEBUG, DEBUG_EMAIL_DIR
import logging
import os
from abc import ABC, abstractmethod
from typing import Dict, Any
import base64
import datetime
import re

# --- Google OAuth Imports ---
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if DEBUG:
    if not os.path.exists(DEBUG_EMAIL_DIR):
        os.makedirs(DEBUG_EMAIL_DIR)

class EmailProvider(ABC):
    def __init__(self, email_address, password, imap_server=None):
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.mail: Any = None

    @abstractmethod
    def connect(self) -> tuple[str, str]:
        pass

    def logout(self) -> None:
        if self.mail:
            self.mail.logout()
            logging.info(f"Disconnected from {self.email_address}")

    def scan_emails(self, num_emails: int = 1000, since_uid: str | None = None, since_date: str | None = None, **kwargs):
        # This implementation can be shared across all IMAP-based providers
        if not self.mail:
            logging.error("Scan attempt failed: Not connected to the email server.")
            yield {"status": "error", "message": "Not connected to the email server."}
            return

        # --- FIX: Login and Select right before scanning for non-Gmail providers ---
        if not isinstance(self, GmailProvider):
            try:
                self.mail.login(self.email_address, self.password)
                status, _ = self.mail.select("inbox")
                if status != 'OK':
                    raise imaplib.IMAP4.error("Failed to select INBOX.")
                logging.info(f"IMAP login and INBOX selection successful for {self.email_address}")
            except Exception as e:
                logging.error(f"IMAP authentication/select failed for {self.email_address}: {e}")
                yield {"status": "error", "message": f"Authentication failed: {e}"}
                return
        
        search_criteria = "ALL"
        if since_date:
            # Format date for IMAP: DD-Mon-YYYY
            try:
                search_date = datetime.datetime.strptime(since_date, "%Y-%m-%d").strftime("%d-%b-%Y")
                search_criteria = f'(SINCE "{search_date}")'
                logging.info(f"Searching for emails since {search_date}")
            except ValueError:
                logging.error(f"Invalid date format for since_date: {since_date}. Use YYYY-MM-DD.")
                # Fallback to default behavior
        elif since_uid:
            search_criteria = f"UID {since_uid}:*"
            logging.info(f"Searching for emails with UID greater than {since_uid}")
        else:
            logging.info("No previous UID or date found, scanning all emails.")

        # We need to fetch UIDs, not message sequence numbers
        status, messages = self.mail.uid('search', None, search_criteria) # type: ignore
        if status != 'OK' or not messages or not messages[0]:
            logging.warning("Failed to retrieve emails or no emails found for the new criteria.")
            yield {"status": "complete", "links": {}, "last_uid": since_uid}
            return

        message_ids = messages[0].split()
        if not since_uid:
            message_ids = message_ids[-num_emails:]
        
        latest_message_ids = message_ids[::-1] # process newest first
        logging.info(f"Found {len(latest_message_ids)} emails to scan.")

        all_unsubscribe_links = {}
        last_uid = None

        if latest_message_ids:
            last_uid = latest_message_ids[0] # The newest one

        total_emails = len(latest_message_ids)
        for i, mail_id in enumerate(latest_message_ids):
            # Fetch using UID
            status, msg_data = self.mail.uid('fetch', mail_id, "(RFC822)")
            if status != "OK":
                logging.warning(f"Failed to fetch email with UID {mail_id}.")
                continue

            if not msg_data or not msg_data[0] or not isinstance(msg_data[0], tuple) or len(msg_data[0]) < 2:
                logging.warning(f"Invalid message data structure for email UID {mail_id}.")
                continue

            raw_email = msg_data[0][1]
            if not isinstance(raw_email, bytes):
                logging.warning(f"Email content for UID {mail_id} is not in bytes.")
                continue

            msg = email.message_from_bytes(raw_email)

            subject_header = msg["Subject"]
            from_ = msg.get("From")
            date_header = msg.get("Date")

            # Parse date
            email_date = None
            if date_header:
                try:
                    email_date = parsedate_to_datetime(date_header).isoformat()
                except Exception:
                    logging.warning(f"Could not parse date string: {date_header}")

            subject = ""
            if subject_header:
                decoded_header = decode_header(subject_header)
                header_parts = []
                for part, encoding in decoded_header:
                    if isinstance(part, bytes):
                        header_parts.append(part.decode(encoding or 'utf-8', 'ignore'))
                    else:
                        header_parts.append(str(part))
                subject = "".join(header_parts)
            
            logging.info(f"Processing email from '{from_}' with subject '{subject}'")

            html_content = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if content_type == "text/html" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload and isinstance(payload, bytes):
                            try:
                                html_content = payload.decode()
                            except (UnicodeDecodeError, AttributeError):
                                try:
                                    html_content = payload.decode('latin-1')
                                except (UnicodeDecodeError, AttributeError):
                                    logging.warning(f"Could not decode multipart HTML for email '{subject}'.")
                                    continue
                        break
            else:
                if msg.get_content_type() == "text/html":
                    payload = msg.get_payload(decode=True)
                    if payload and isinstance(payload, bytes):
                        try:
                            html_content = payload.decode()
                        except (UnicodeDecodeError, AttributeError):
                            try:
                                html_content = payload.decode('latin-1')
                            except (UnicodeDecodeError, AttributeError):
                                logging.warning(f"Could not decode single part HTML for email '{subject}'.")
                                pass

            if html_content:
                if DEBUG:
                    try:
                        safe_subject = "".join([c for c in subject if c.isalpha() or c.isdigit() or c in (' ', '-')]).rstrip()
                        filename = f"{DEBUG_EMAIL_DIR}/{mail_id.decode()}_{safe_subject}.html"
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(html_content)
                        logging.info(f"Saved email HTML to {filename}")
                    except Exception as e:
                        logging.error(f"Failed to save email HTML: {e}")

                yield {
                    "status": "progress",
                    "progress": i + 1,
                    "total": total_emails,
                    "current_email_subject": subject
                }

                links = find_unsubscribe_links(html_content)
                if links:
                    logging.info(f"Found {len(links)} unsubscribe links in email '{subject}'.")
                    sender_domain = ""
                    if from_ and '@' in from_:
                        sender_domain = from_.split('@')[-1].replace('>', '')
                    elif from_:
                        sender_domain = from_

                    if sender_domain:
                        if sender_domain not in all_unsubscribe_links:
                            all_unsubscribe_links[sender_domain] = []
                        for link_data in links:
                            link_data['subject'] = subject
                            link_data['date'] = email_date
                            all_unsubscribe_links[sender_domain].append(link_data)

        final_uid = last_uid.decode('utf-8') if isinstance(last_uid, bytes) else last_uid
        yield {"status": "complete", "links": all_unsubscribe_links, "last_uid": final_uid}


class IMAPProvider(EmailProvider):
    def connect(self) -> tuple[str, str]:
        if not self.imap_server:
            return "ERROR", "IMAP server is required for this provider."
        try:
            # Only create the connection object here. Login/select will be done in scan_emails.
            self.mail = imaplib.IMAP4_SSL(self.imap_server)
            logging.info(f"Successfully created IMAP SSL object for {self.imap_server}")
            return "OK", "Successfully created IMAP connection object."
        except Exception as e:
            logging.error(f"Failed to create IMAP connection for {self.imap_server}: {e}")
            return "ERROR", f"Failed to create IMAP connection: {e}"

    # This provider uses the default scan_emails from EmailProvider and logout from EmailProvider

class GmailProvider(EmailProvider):
    def __init__(self, email_address: str, credentials_info: Dict[str, Any]):
        super().__init__(email_address, password=None) # No password for OAuth
        self.credentials = Credentials.from_authorized_user_info(credentials_info)
        self.service = None

    def connect(self) -> tuple[str, str]:
        try:
            self.service = build('gmail', 'v1', credentials=self.credentials)
            # Test connection by getting profile info
            self.service.users().getProfile(userId='me').execute() # type: ignore
            logging.info("Successfully connected to Gmail API.")
            return "OK", "Connected to Gmail successfully."
        except HttpError as error:
            logging.error(f"An error occurred with Gmail API: {error}")
            return "ERROR", f"API Error: {error}"
        except Exception as e:
            logging.error(f"Failed to connect to Gmail: {e}")
            return "ERROR", f"Failed to connect: {e}"

    def logout(self) -> None:
        self.service = None
        logging.info("Disconnected from Gmail (no action needed).")

    def scan_emails(self, num_emails: int = 1000, since_date: str | None = None, **kwargs):
        if not self.service:
            logging.error("Scan attempt failed: Not connected to the Gmail API.")
            yield {"status": "error", "message": "Not connected to the Gmail API."}
            return

        query = ""
        if since_date:
            try:
                # Format for Gmail API: YYYY/MM/DD
                search_date = datetime.datetime.strptime(since_date, "%Y-%m-%d").strftime("%Y/%m/%d")
                query = f"after:{search_date}"
                logging.info(f"Searching Gmail for emails after {search_date}")
            except ValueError:
                logging.error(f"Invalid date format for since_date: {since_date}. Use YYYY-MM-DD.")

        try:
            response = self.service.users().messages().list(userId='me', maxResults=num_emails, q=query).execute() # type: ignore
            messages = response.get('messages', [])
            
            all_unsubscribe_links = {}
            email_dates = []

            if not messages:
                logging.info("No new messages found in Gmail.")
                yield {
                    "status": "complete", 
                    "links": {}, 
                    "description": "Scan complete", 
                    "date_range": "No new emails found"
                }
                return

            total_emails = len(messages)
            for i, message_info in enumerate(messages):
                msg_id = message_info['id']
                msg = self.service.users().messages().get(userId='me', id=msg_id, format='full').execute() # type: ignore

                payload = msg.get('payload', {})
                headers = payload.get('headers', [])
                
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                from_ = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
                date_str = next((h['value'] for h in headers if h['name'].lower() == 'date'), None)
                
                email_date = None
                if date_str:
                    try:
                        dt_object = parsedate_to_datetime(date_str)
                        if dt_object.tzinfo is None:
                            dt_object = dt_object.replace(tzinfo=datetime.timezone.utc)
                        email_date = dt_object.isoformat()
                        email_dates.append(dt_object)
                    except Exception:
                        logging.warning(f"Could not parse date string: {date_str}")
                
                html_content = ""
                parts = payload.get('parts', [])
                if parts: # It's a multipart message
                    for part in parts:
                        if part['mimeType'] == 'text/html':
                            body = part.get('body', {})
                            data = body.get('data')
                            if data:
                                html_content = base64.urlsafe_b64decode(data).decode('utf-8')
                                break
                elif payload.get('mimeType') == 'text/html': # It's a single part message
                     body_data = payload.get('body', {}).get('data')
                     if body_data:
                        html_content = base64.urlsafe_b64decode(body_data).decode('utf-8')

                if html_content:
                    yield { "status": "progress", "progress": i + 1, "total": total_emails, "current_email_subject": subject }
                    links = find_unsubscribe_links(html_content)
                    if links:
                        sender_domain = ""
                        match = re.search(r'@([\w.-]+)', from_)
                        if match:
                            sender_domain = match.group(1).replace('>', '')
                        
                        if sender_domain:
                            if sender_domain not in all_unsubscribe_links:
                                all_unsubscribe_links[sender_domain] = []
                            for link_data in links:
                                link_data['subject'] = subject
                                link_data['date'] = email_date
                                all_unsubscribe_links[sender_domain].append(link_data)
            
            date_range_str = ""
            if email_dates:
                min_date = min(email_dates).strftime('%Y-%m-%d')
                max_date = max(email_dates).strftime('%Y-%m-%d')
                date_range_str = f"from {min_date} to {max_date}"

            scan_description = f"Scanned {num_emails} recent emails" if not since_date else f"Scanned emails since {since_date}"

            yield {
                "status": "complete", 
                "links": all_unsubscribe_links,
                "description": scan_description,
                "date_range": date_range_str
            }

        except HttpError as error:
            logging.error(f"An API error occurred during Gmail scan: {error}")
            yield {"status": "error", "message": f"API Error: {error}"}
        except Exception as e:
            logging.error(f"An unexpected error occurred during Gmail scan: {e}")
            yield {"status": "error", "message": f"An unexpected error occurred: {e}"}


class OutlookProvider(EmailProvider):
    # Future implementation will use OAuth2
    def connect(self) -> tuple[str, str]:
        # To be implemented with OAuth2
        return "ERROR", "Outlook provider is not yet implemented."

    def logout(self) -> None:
        pass


def get_email_client(provider_name, email_address, password_or_creds, imap_server=None):
    if provider_name == "gmail":
        return GmailProvider(email_address, credentials_info=password_or_creds)
    elif provider_name == "outlook":
        # This will be updated to use OAuth credentials
        return OutlookProvider(email_address, password_or_creds, "imap-mail.outlook.com")
    elif provider_name == "other":
        return IMAPProvider(email_address, password_or_creds, imap_server)
    else:
        raise ValueError("Unsupported email provider")
