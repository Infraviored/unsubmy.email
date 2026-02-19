from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, Text, ForeignKey, UniqueConstraint
import datetime
from datetime import timezone

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=True)
    accounts: Mapped[list["LinkedAccount"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    unsubscribe_links: Mapped[list["UnsubscribeLink"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LinkedAccount(db.Model):
    __tablename__ = 'linked_account'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    email_address: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    imap_server: Mapped[str] = mapped_column(String(120), nullable=True)
    credentials: Mapped[str] = mapped_column(Text, nullable=True) # For storing encrypted credentials/tokens
    last_scan_date: Mapped[datetime.datetime] = mapped_column(nullable=True)
    
    owner: Mapped["User"] = relationship(back_populates="accounts")
    unsubscribe_links: Mapped[list["UnsubscribeLink"]] = relationship(back_populates="linked_account", cascade="all, delete-orphan")

class UnsubscribeLink(db.Model):
    __tablename__ = 'unsubscribe_link'
    __table_args__ = (UniqueConstraint('user_id', 'unsubscribe_url', name='_user_url_uc'),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'), nullable=False)
    linked_account_id: Mapped[int] = mapped_column(ForeignKey('linked_account.id'), nullable=True) # Can be nullable for older links
    list_name: Mapped[str] = mapped_column(String(255), nullable=False)
    unsubscribe_url: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=True)
    link_text: Mapped[str] = mapped_column(Text, nullable=True)
    added_at: Mapped[datetime.datetime] = mapped_column(default=lambda: datetime.datetime.now(timezone.utc), nullable=False)
    unsubscribed: Mapped[bool] = mapped_column(default=False, nullable=False)
    unsubscribed_at: Mapped[datetime.datetime] = mapped_column(nullable=True)

    user: Mapped["User"] = relationship(back_populates="unsubscribe_links") 
    linked_account: Mapped["LinkedAccount"] = relationship(back_populates="unsubscribe_links") 