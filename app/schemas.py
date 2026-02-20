from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class AccountBase(BaseModel):
    email_address: EmailStr
    provider: str

class AccountAdd(AccountBase):
    password: Optional[str] = None
    imap_server: Optional[str] = None

class AccountUpdate(BaseModel):
    email_address: EmailStr
    password: Optional[str] = None
    imap_server: Optional[str] = None

class UnsubscribeBase(BaseModel):
    href: str
    delete_others: bool = False

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
