import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import (
    User as UserSchema,
    InfluencerProfile,
    BusinessProfile,
    Booking,
    Message,
    Visit,
)

# App setup
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Helpers
class IdResponse(BaseModel):
    id: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class PublicUser(BaseModel):
    id: str
    email: EmailStr
    name: str
    role: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email})


def to_public_user(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(doc.get("_id")),
        "email": doc.get("email"),
        "name": doc.get("name"),
        "role": doc.get("role"),
    }


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(email)
    if user is None:
        raise credentials_exception
    return user


def require_role(user: dict, role: str):
    if user.get("role") != role:
        raise HTTPException(status_code=403, detail="Forbidden")


def to_public_influencer(doc: Dict[str, Any]) -> Dict[str, Any]:
    metrics = doc.get("metrics", {}) or {}
    def sum_platform(p):
        m = metrics.get(p) or {}
        return int(m.get("followers") or 0)
    return {
        "id": str(doc.get("_id")),
        "display_name": doc.get("display_name"),
        "city": doc.get("city"),
        "categories": doc.get("categories", []),
        "budget_min": int(doc.get("budget_min", 0)),
        "budget_max": int(doc.get("budget_max", 0)),
        "metrics_summary": {
            "instagram": sum_platform("instagram"),
            "facebook": sum_platform("facebook"),
            "youtube": sum_platform("youtube"),
        },
        "avatar_url": None,
    }


@app.get("/")
def read_root():
    return {"message": "Influencer Marketplace API"}


@app.get("/schema")
def get_schema():
    from schemas import (
        User, InfluencerProfile, BusinessProfile, Booking, Message, Visit
    )
    return {
        "user": User.model_json_schema(),
        "influencerprofile": InfluencerProfile.model_json_schema(),
        "businessprofile": BusinessProfile.model_json_schema(),
        "booking": Booking.model_json_schema(),
        "message": Message.model_json_schema(),
        "visit": Visit.model_json_schema(),
    }


# Auth models & routes
class SignupRequest(BaseModel):
    email: EmailStr
    name: str
    role: str  # influencer | business | admin
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(payload.password)
    user = UserSchema(email=payload.email, password_hash=hashed, name=payload.name, role=payload.role)
    new_id = create_document("user", user)
    token = create_access_token({"sub": payload.email})
    db["user"].update_one({"_id": ObjectId(new_id)}, {"$set": {"token": token}})
    return {"access_token": token}


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token({"sub": payload.email})
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"token": token, "updated_at": datetime.now(timezone.utc)}})
    return {"access_token": token}


@app.get("/me", response_model=PublicUser)
def get_me(current_user: dict = Depends(get_current_user)):
    return to_public_user(current_user)


# Influencer profile CRUD
@app.post("/influencers", response_model=IdResponse)
def create_influencer_profile(profile: InfluencerProfile, current_user: dict = Depends(get_current_user)):
    # Only allow owner to create their profile
    if str(profile.user_id) != str(current_user.get("_id")) and (ObjectId.is_valid(profile.user_id) and str(ObjectId(profile.user_id)) != str(current_user.get("_id"))):
        raise HTTPException(status_code=403, detail="Cannot create profile for another user")
    user = db["user"].find_one({"_id": ObjectId(profile.user_id)}) if ObjectId.is_valid(profile.user_id) else None
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_id = create_document("influencerprofile", profile)
    return {"id": new_id}


@app.get("/influencers")
def list_influencers(
    city: Optional[str] = None,
    min_budget: Optional[int] = Query(None, ge=0),
    max_budget: Optional[int] = Query(None, ge=0),
    category: Optional[str] = None,
    min_followers: Optional[int] = Query(None, ge=0),
    limit: int = 50,
):
    q: Dict[str, Any] = {}
    if city:
        q["city"] = {"$regex": f"^{city}$", "$options": "i"}
    if min_budget is not None or max_budget is not None:
        budget_filters = []
        if min_budget is not None:
            budget_filters.append({"budget_max": {"$gte": min_budget}})
        if max_budget is not None:
            budget_filters.append({"budget_min": {"$lte": max_budget}})
        if budget_filters:
            q["$and"] = budget_filters
    if category:
        q["categories"] = {"$in": [category]}
    if min_followers is not None:
        q["$or"] = [
            {"metrics.instagram.followers": {"$gte": min_followers}},
            {"metrics.facebook.followers": {"$gte": min_followers}},
            {"metrics.youtube.followers": {"$gte": min_followers}},
        ]

    items = get_documents("influencerprofile", q, limit)
    return [to_public_influencer(doc) for doc in items]


@app.get("/influencers/{influencer_id}")
def get_influencer(influencer_id: str):
    if not ObjectId.is_valid(influencer_id):
        raise HTTPException(status_code=400, detail="Invalid id")
    doc = db["influencerprofile"].find_one({"_id": ObjectId(influencer_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    # Track visit (anonymous)
    db["influencerprofile"].update_one({"_id": doc["_id"]}, {"$inc": {"visits": 1}})
    doc["id"] = influencer_id
    doc["_id"] = str(doc["_id"])  # for frontend safety
    return doc


# Business profile
@app.post("/business", response_model=IdResponse)
def create_business_profile(profile: BusinessProfile, current_user: dict = Depends(get_current_user)):
    # Only allow owner to create their profile
    if str(profile.user_id) != str(current_user.get("_id")) and (ObjectId.is_valid(profile.user_id) and str(ObjectId(profile.user_id)) != str(current_user.get("_id"))):
        raise HTTPException(status_code=403, detail="Cannot create profile for another user")
    user = db["user"].find_one({"_id": ObjectId(profile.user_id)}) if ObjectId.is_valid(profile.user_id) else None
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_id = create_document("businessprofile", profile)
    return {"id": new_id}


# Booking
@app.post("/bookings", response_model=IdResponse)
def create_booking(booking: Booking, current_user: dict = Depends(get_current_user)):
    # Business initiates by default
    if not ObjectId.is_valid(booking.influencer_id) or not ObjectId.is_valid(booking.business_id):
        raise HTTPException(status_code=400, detail="Invalid ids")
    new_id = create_document("booking", booking)
    return {"id": new_id}


@app.get("/influencers/{influencer_id}/bookings")
def list_influencer_bookings(influencer_id: str, current_user: dict = Depends(get_current_user)):
    if not ObjectId.is_valid(influencer_id):
        raise HTTPException(status_code=400, detail="Invalid id")
    items = get_documents("booking", {"influencer_id": influencer_id})
    return items


# Messages / Chat
@app.post("/messages", response_model=IdResponse)
def send_message(msg: Message, current_user: dict = Depends(get_current_user)):
    new_id = create_document("message", msg)
    return {"id": new_id}


@app.get("/conversations/{conversation_id}/messages")
def get_messages(conversation_id: str, limit: int = 100, current_user: dict = Depends(get_current_user)):
    items = get_documents("message", {"conversation_id": conversation_id}, limit)
    return items


# Dashboards
@app.get("/dashboard/influencer")
def dashboard_influencer(current_user: dict = Depends(get_current_user)):
    require_role(current_user, "influencer")
    # Find influencer profile id
    prof = db["influencerprofile"].find_one({"user_id": str(current_user.get("_id"))})
    if not prof:
        return {"profile": None, "bookings": [], "messages": [], "visits": 0}
    influencer_id = str(prof.get("_id"))
    bookings = get_documents("booking", {"influencer_id": influencer_id})
    messages = list(db["message"].find({"$or": [{"sender_id": influencer_id}, {"receiver_id": influencer_id}]}).sort("created_at", -1).limit(50))
    visits = int(prof.get("visits", 0))
    return {"profile": {"id": influencer_id, "display_name": prof.get("display_name"), "city": prof.get("city")}, "bookings": bookings, "messages": messages, "visits": visits}


@app.get("/dashboard/business")
def dashboard_business(current_user: dict = Depends(get_current_user)):
    require_role(current_user, "business")
    prof = db["businessprofile"].find_one({"user_id": str(current_user.get("_id"))})
    if not prof:
        return {"profile": None, "bookings": [], "messages": []}
    business_id = str(prof.get("_id"))
    bookings = get_documents("booking", {"business_id": business_id})
    messages = list(db["message"].find({"$or": [{"sender_id": business_id}, {"receiver_id": business_id}]}).sort("created_at", -1).limit(50))
    return {"profile": {"id": business_id, "business_name": prof.get("business_name")}, "bookings": bookings, "messages": messages}


@app.get("/admin/summary")
def admin_summary(current_user: dict = Depends(get_current_user)):
    require_role(current_user, "admin")
    return {
        "users": db["user"].count_documents({}),
        "influencers": db["influencerprofile"].count_documents({}),
        "businesses": db["businessprofile"].count_documents({}),
        "bookings": db["booking"].count_documents({}),
        "messages": db["message"].count_documents({}),
    }


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
