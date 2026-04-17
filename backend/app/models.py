from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Source = Literal["phone", "checkin", "manual", "plan"]
MinuteSource = Literal["phone", "checkin", "manual", "gap"]


class BlockIn(BaseModel):
    client_id: str = Field(max_length=64)
    start_ts: datetime
    end_ts: datetime
    source: Source
    app: str | None = Field(default=None, max_length=128)
    activity: str | None = Field(default=None, max_length=255)
    category: str | None = Field(default=None, max_length=64)


class BlockOut(BlockIn):
    id: int


class BlocksBatch(BaseModel):
    blocks: list[BlockIn]


class PlannedBlockIn(BaseModel):
    day: str
    start_ts: datetime
    end_ts: datetime
    category: str | None = None
    note: str | None = None


class SummaryBucket(BaseModel):
    category: str
    minutes: int


class TodaySummary(BaseModel):
    date: str
    total_minutes: int
    accounted_minutes: int
    unaccounted_minutes: int
    buckets: list[SummaryBucket]
