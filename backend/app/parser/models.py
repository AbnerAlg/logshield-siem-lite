from pydantic import BaseModel, Field
from datetime import datetime 

class LogEntry(BaseModel):
    """Represents a fully parsed and validated log entry. """
    ip_address: str = Field (..., description = "Client IPv4 address ")
    timestamp: datetime = Field (..., description = "Event date and time")
    method: str = Field(..., description = "Method HTTP (GET, POST, etc.)")
    path: str = Field(..., description = "Requested URL path or endpoint ")
    status_code: int = Field(..., description = "HTTP response status code (e.g., 200, 401)")
    size: int = Field(..., description = "Response Size in bytes")