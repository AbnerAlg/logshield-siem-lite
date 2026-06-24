from pydantic import BaseModel, Field 
from datetime import datetime
from typing import List, Optional

class SecurityAlert(BaseModel):
    """ Represents a security alert triggered by the Rule Engine """
    id: str = Field(...,description = "Unique identifier for the alert (e.g., IP_RULE_TIMESTAMP)")
    rule_name: str = Field(..., description = "Name of the violated security rule")
    severity: str = Field(..., description = "Saverity Level: LOW, MEDIUM, HIGH, CRITICAL")
    source_ip: str = Field(..., description = "The IP Address responsible for the anomaly")
    description: str = Field(..., description = "Detailed explanation of what triggered the alert")
    timestamp: datetime = Field(..., description = "Time when the alert was generated")
    triggered_by_status: Optional[int] = Field(None, description = "HTTP status involved if applicable")
