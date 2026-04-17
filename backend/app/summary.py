from datetime import date, datetime, time, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import current_user_id
from .db import get_db
from .models import SummaryBucket, TodaySummary

router = APIRouter(prefix="/v1", tags=["summary"])


@router.get("/summary/today", response_model=TodaySummary)
def today_summary(
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> TodaySummary:
    today = date.today()
    start = datetime.combine(today, time.min)
    end = start + timedelta(days=1)

    rows = db.execute(
        text(
            """
            SELECT COALESCE(category, 'uncategorized') AS category,
                   SUM(CASE WHEN source = 'gap' THEN 0 ELSE 1 END) AS accounted,
                   COUNT(*) AS total
            FROM minutes
            WHERE user_id = :u AND ts >= :s AND ts < :e
            GROUP BY category
            """
        ),
        {"u": user_id, "s": start, "e": end},
    ).mappings().all()

    buckets: list[SummaryBucket] = []
    total = 0
    accounted = 0
    for r in rows:
        accounted_here = int(r["accounted"])
        total_here = int(r["total"])
        total += total_here
        accounted += accounted_here
        if accounted_here:
            buckets.append(
                SummaryBucket(category=r["category"], minutes=accounted_here)
            )
    buckets.sort(key=lambda b: -b.minutes)
    return TodaySummary(
        date=today.isoformat(),
        total_minutes=total,
        accounted_minutes=accounted,
        unaccounted_minutes=total - accounted,
        buckets=buckets,
    )
