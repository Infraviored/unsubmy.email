import asyncio
import json
import datetime
from datetime import timezone
from celery import Celery
from sqlalchemy import select
from app.models import AsyncSessionLocal, User, LinkedAccount, UnsubscribeLink, WhitelistedDomain
from app.email_client import get_email_client
import os
import redis.asyncio as redis
import logging

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
celery = Celery('worker', broker=REDIS_URL, backend=CELERY_RESULT_BACKEND)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_concurrency=int(os.getenv("CELERY_WORKER_CONCURRENCY", "4")),
)

# We will create the redis manager inside the task to avoid event loop issues

@celery.task(name='scan_emails')
def scan_emails_task(user_id, account_id, num_emails=None, since_date=None):
    return asyncio.run(run_scan(user_id, account_id, num_emails, since_date))

async def run_scan(user_id, account_id, num_emails, since_date):
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.models import DATABASE_URL, DATABASE_ECHO
    # Create an ephemeral engine for this event loop to avoid cross-loop issues in Celery
    engine = create_async_engine(DATABASE_URL, echo=DATABASE_ECHO)
    LocalSession = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    
    logger.info(f"Starting scan for user {user_id}, account {account_id}")
    progress_channel = f"scan_progress_{user_id}_{account_id}"
    
    # Create a fresh redis manager for this loop
    redis_manager = redis.from_url(REDIS_URL)
    
    async with LocalSession() as db:
        client = None
        try:
            # Fetch account
            result = await db.execute(
                select(LinkedAccount).where(LinkedAccount.id == account_id, LinkedAccount.user_id == user_id)
            )
            account = result.scalar_one_or_none()
            if not account:
                logger.error("Account not found")
                await redis_manager.publish(progress_channel, json.dumps({"error": "Account not found"}))
                return {"error": "Account not found"}

            creds_dict = account.get_credentials()
            if not creds_dict or (account.provider != 'gmail' and not creds_dict.get('password')):
                err_msg = "Missing credentials or password for account"
                logger.error(err_msg)
                await redis_manager.publish(progress_channel, json.dumps({"error": err_msg}))
                return {"error": err_msg}

            password_or_creds = creds_dict if account.provider == 'gmail' else creds_dict.get('password')

            client = get_email_client(
                account.provider, 
                account.email_address, 
                password_or_creds, 
                account.imap_server
            )
            status_code, msg = client.connect()
            if status_code == "ERROR":
                logger.error(f"Connection failed: {msg}")
                await redis_manager.publish(progress_channel, json.dumps({"error": f"Connection failed: {msg}"}))
                return {"error": msg}

            scan_params = {}
            if num_emails: scan_params['num_emails'] = int(num_emails)
            if since_date: scan_params['since_date'] = since_date
            
            # Optimization: get existing urls
            e_stmt = select(UnsubscribeLink.unsubscribe_url).where(UnsubscribeLink.user_id == user_id)
            e_result = await db.execute(e_stmt)
            existing_urls = set(e_result.scalars().all())

            # Get whitelisted domains
            w_stmt = select(WhitelistedDomain.domain).where(WhitelistedDomain.user_id == user_id)
            w_result = await db.execute(w_stmt)
            whitelisted = set(w_result.scalars().all())

            new_links_found = 0
            new_links_to_add = []
            
            # scan_emails is a synchronous generator
            for progress_update in client.scan_emails(**scan_params):
                if 'links' in progress_update:
                    new_links_payload = progress_update.get('links', {})
                    for domain, links_list in new_links_payload.items():
                        if domain in whitelisted:
                            continue
                        for link_info in links_list:
                            url = link_info['href']
                            if url not in existing_urls:
                                new_link = UnsubscribeLink(
                                    user_id=user_id,
                                    linked_account_id=account.id,
                                    list_name=link_info.get('from', domain),
                                    unsubscribe_url=url,
                                    subject=link_info.get('subject'),
                                    link_text=link_info.get('text'),
                                    added_at=datetime.datetime.now(timezone.utc)
                                )
                                # Some basic date parsing if available
                                if link_info.get('date'):
                                    try:
                                        new_link.added_at = datetime.datetime.fromisoformat(link_info['date'])
                                    except (ValueError, TypeError):
                                        pass
                                    
                                new_links_to_add.append(new_link)
                                existing_urls.add(url)
                                new_links_found += 1
                else:
                    # Publish progress to Redis
                    await redis_manager.publish(progress_channel, json.dumps(progress_update))
            
            if new_links_to_add:
                db.add_all(new_links_to_add)

            # Final update AFTER loop finishes
            account.last_scan_date = datetime.datetime.now(timezone.utc)
            await db.commit()
            await redis_manager.publish(progress_channel, json.dumps({'status': 'complete', 'new_links_found': new_links_found}))
            
            logger.info(f"Scan complete for user {user_id}. Found {new_links_found} links.")
            return {"status": "complete", "new_links_found": new_links_found}
            
        except Exception as e:
            logger.exception("Task failed")
            try:
                await db.rollback()
            except Exception:
                logger.exception("Failed to rollback database session")
            await redis_manager.publish(progress_channel, json.dumps({"error": str(e)}))
            return {"error": str(e)}
        finally:
            if client:
                try:
                    client.logout()
                except Exception:
                    pass
            # Clean up redis connection
            await redis_manager.close()
            # Crucial: Dispose engine connections to avoid cross-loop issues in next task
            await engine.dispose()
