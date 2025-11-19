"""
Database Schemas for Influencer Marketplace

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).

Collections:
- User: Auth users with roles (influencer, business, admin)
- InfluencerProfile: Public profile of influencers
- BusinessProfile: Business details for brand/users
- Booking: Booking requests between business and influencer
- Message: Chat messages between business and influencer
- Visit: Profile visit tracking for influencers
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal, Dict

RoleType = Literal["influencer", "business", "admin"]
PlatformType = Literal["instagram", "facebook", "youtube"]

class SocialLinks(BaseModel):
    instagram: Optional[str] = Field(None, description="Instagram profile URL")
    facebook: Optional[str] = Field(None, description="Facebook profile URL")
    youtube: Optional[str] = Field(None, description="YouTube channel URL")

class PlatformMetrics(BaseModel):
    followers: Optional[int] = Field(0, ge=0)
    avg_likes: Optional[int] = Field(0, ge=0)
    avg_comments: Optional[int] = Field(0, ge=0)
    engagement_rate: Optional[float] = Field(0.0, ge=0.0)

class Metrics(BaseModel):
    instagram: Optional[PlatformMetrics] = PlatformMetrics()
    facebook: Optional[PlatformMetrics] = PlatformMetrics()
    youtube: Optional[PlatformMetrics] = PlatformMetrics()

class User(BaseModel):
    email: EmailStr
    password_hash: str
    name: str
    role: RoleType = "business"
    token: Optional[str] = None

class InfluencerProfile(BaseModel):
    user_id: str
    display_name: str
    budget_min: int = Field(0, ge=0)
    budget_max: int = Field(0, ge=0)
    city: str
    location: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    phone: Optional[str] = None
    categories: List[str] = []
    social_links: Optional[SocialLinks] = SocialLinks()
    metrics: Optional[Metrics] = Metrics()
    bio: Optional[str] = None
    visits: int = 0

class BusinessProfile(BaseModel):
    user_id: str
    business_name: str
    city: Optional[str] = None
    industry: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    phone: Optional[str] = None
    description: Optional[str] = None

class Booking(BaseModel):
    influencer_id: str
    business_id: str
    status: Literal["pending", "accepted", "rejected", "completed"] = "pending"
    campaign_brief: Optional[str] = None
    budget_offer: Optional[int] = None
    notes: Optional[str] = None

class Message(BaseModel):
    conversation_id: str  # business_id:influencer_id
    sender_id: str
    receiver_id: str
    text: str

class Visit(BaseModel):
    influencer_id: str
    viewer_id: Optional[str] = None

# Response helpers
class PublicInfluencer(BaseModel):
    id: str
    display_name: str
    city: str
    categories: List[str]
    budget_min: int
    budget_max: int
    metrics_summary: Dict[str, int] = {}
    avatar_url: Optional[str] = None
