from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, Text, ForeignKey, UniqueConstraint, DateTime
import datetime
from datetime import timezone
import os

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
engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session