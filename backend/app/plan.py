from datetime import date, datetime, time, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import current_user_id
from .db import get_db
from .models import PlannedBlockIn

router = APIRouter(prefix="/v1", tags=["plan"])


@router.post("/plan", status_code=201)
def save_plan(
    blocks: list[PlannedBlockIn],
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    if not blocks:
        return {"saved": 0}
    days = {datetime.strptime(b.day, "%Y-%m-%d").date() for b in blocks}
    for day in days:
        db.execute(
            text("DELETE FROM planned_blocks WHERE user_id = :u AND day = :d"),
            {"u": user_id, "d": day},
        )
    for b in blocks:
        db.execute(
            text(
                """
                INSERT INTO planned_blocks
                  (user_id, day, start_ts, end_ts, category, note)
                VALUES (:u, :d, :s, :e, :c, :n)
                """
            ),
            {
                "u": user_id,
                "d": datetime.strptime(b.day, "%Y-%m-%d").date(),
                "s": b.start_ts,
                "e": b.end_ts,
                "c": b.category,
                "n": b.note,
            },
        )
    db.commit()
    return {"saved": len(blocks)}


@router.get("/plan")
def get_plan(
    day: str = Query(default_factory=lambda: date.today().isoformat()),
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> list[dict]:
    d = datetime.strptime(day, "%Y-%m-%d").date()
    rows = db.execute(
        text(
            """
            SELECT id, start_ts, end_ts, category, note
            FROM planned_blocks
            WHERE user_id = :u AND day = :d
            ORDER BY start_ts
            """
        ),
        {"u": user_id, "d": d},
    ).mappings().all()
    return [dict(r) for r in rows]
