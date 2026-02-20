from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, Text, ForeignKey, UniqueConstraint, DateTime
import datetime
from datetime import timezone
import os
import json
import base64
import hashlib
from cryptography.fernet import Fernet

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=True)
    
    accounts: Mapped[list["LinkedAccount"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    unsubscribe_links: Mapped[list["UnsubscribeLink"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class LinkedAccount(Base):
    __tablename__ = 'linked_account'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    email_address: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    imap_server: Mapped[str] = mapped_column(String(120), nullable=True)
    credentials: Mapped[str] = mapped_column(Text, nullable=True)
    last_scan_date: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    
    owner: Mapped["User"] = relationship(back_populates="accounts")
    unsubscribe_links: Mapped[list["UnsubscribeLink"]] = relationship(back_populates="linked_account", cascade="all, delete-orphan")

    def _get_cipher(self):
        secret = os.getenv("SECRET_KEY")
        if not secret or secret in ["change-me-in-production", "a-secure-secret-key-for-sessions"]:
            import logging
            logging.warning("SECRET_KEY not set or using insecure default. Credentials may be easily compromised!")
            secret = secret or "a-secure-secret-key-for-sessions-fallback-123"
        
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        return Fernet(key)

    def set_credentials(self, creds_dict: dict):
        cipher = self._get_cipher()
        creds_json = json.dumps(creds_dict)
        self.credentials = cipher.encrypt(creds_json.encode()).decode()

    def get_credentials(self) -> dict:
        if not self.credentials:
            return {}
        cipher = self._get_cipher()
        try:
            decrypted = cipher.decrypt(self.credentials.encode()).decode()
            return json.loads(decrypted)
        except Exception:
            # Fallback for old plaintext data during transition
            try:
                import logging
                logging.warning(f"Using plaintext fallback for account {self.id}. Please re-link account to encrypt credentials.")
                return json.loads(self.credentials)
            except:
                return {}

class UnsubscribeLink(Base):
    __tablename__ = 'unsubscribe_link'
    __table_args__ = (UniqueConstraint('user_id', 'unsubscribe_url', name='_user_url_uc'),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'), nullable=False)
    linked_account_id: Mapped[int] = mapped_column(ForeignKey('linked_account.id'), nullable=True)
    list_name: Mapped[str] = mapped_column(String(255), nullable=False)
    unsubscribe_url: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=True)
    link_text: Mapped[str] = mapped_column(Text, nullable=True)
    added_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc), nullable=False)
    unsubscribed: Mapped[bool] = mapped_column(default=False, nullable=False)
    unsubscribed_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="unsubscribe_links") 
    linked_account: Mapped["LinkedAccount"] = relationship(back_populates="unsubscribe_links")

# Database session management
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost/unsubmyemail")
DATABASE_ECHO = os.getenv("DATABASE_ECHO", "false").lower() in ("true", "1", "yes")
engine = create_async_engine(DATABASE_URL, echo=DATABASE_ECHO)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session