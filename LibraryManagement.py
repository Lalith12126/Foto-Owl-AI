from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from typing import List
from datetime import datetime
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI()
Base = declarative_base()
DATABASE_URL = "sqlite:///./library.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBasic()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

ADMIN = "admin"
USER = "user"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default=USER)
    borrow_requests = relationship("BookRequest", back_populates="user")

class Book(Base):
    __tablename__ = "books"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    author = Column(String)
    copies_available = Column(Integer)
    borrow_requests = relationship("BookRequest", back_populates="book")

class BookRequest(Base):
    __tablename__ = "book_requests"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    book_id = Column(Integer, ForeignKey("books.id"))
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    status = Column(String, default="pending")
    user = relationship("User", back_populates="borrow_requests")
    book = relationship("Book", back_populates="borrow_requests")
    __table_args__ = (
        UniqueConstraint("book_id", "start_date", "end_date", name="unique_booking"),
    )

Base.metadata.create_all(bind=engine)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if user and verify_password(password, user.hashed_password):
        return user
    return None

def get_current_user(credentials: HTTPBasicCredentials, db=Depends(get_db)):
    user = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user

def get_admin_user(credentials: HTTPBasicCredentials, db=Depends(get_db)):
    user = get_current_user(credentials, db)
    if user.role != ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user

@app.post("/users/", response_model=dict)
def create_user(email: str, password: str, db: SessionLocal = Depends(get_db)):
    hashed_password = get_password_hash(password)
    new_user = User(email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

@app.get("/books/", response_model=List[dict])
def get_books(db: SessionLocal = Depends(get_db)):
    return db.query(Book).all()

@app.post("/books/", response_model=dict)
def add_book(title: str, author: str, copies: int, db: SessionLocal = Depends(get_db), admin=Depends(get_admin_user)):
    book = Book(title=title, author=author, copies_available=copies)
    db.add(book)
    db.commit()
    db.refresh(book)
    return {"message": "Book added successfully"}

@app.post("/borrow/", response_model=dict)
def borrow_book(book_id: int, start_date: datetime, end_date: datetime, db: SessionLocal = Depends(get_db), user=Depends(get_current_user)):
    if start_date >= end_date:
        raise HTTPException(status_code=400, detail="Invalid borrow dates")
    book = db.query(Book).filter(Book.id == book_id).first()
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    if book.copies_available <= 0:
        raise HTTPException(status_code=400, detail="No copies available")
    overlapping_request = db.query(BookRequest).filter(
        BookRequest.book_id == book_id,
        BookRequest.start_date < end_date,
        BookRequest.end_date > start_date,
        BookRequest.status == "approved",
    ).first()
    if overlapping_request:
        raise HTTPException(status_code=400, detail="Book already borrowed for the selected dates")
    request = BookRequest(user_id=user.id, book_id=book_id, start_date=start_date, end_date=end_date)
    book.copies_available -= 1
    db.add(request)
    db.commit()
    db.refresh(request)
    return {"message": "Borrow request submitted"}

@app.get("/requests/", response_model=List[dict])
def view_requests(db: SessionLocal = Depends(get_db), admin=Depends(get_admin_user)):
    return db.query(BookRequest).all()

@app.patch("/requests/{request_id}/", response_model=dict)
def approve_or_deny_request(request_id: int, status: str, db: SessionLocal = Depends(get_db), admin=Depends(get_admin_user)):
    request = db.query(BookRequest).filter(BookRequest.id == request_id).first()
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    if status not in ["approved", "denied"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    request.status = status
    if status == "denied":
        request.book.copies_available += 1
    db.commit()
    return {"message": f"Request {status}"}
