"""Reconcile overlapping blocks into a per-minute view.

Priority when multiple blocks cover the same minute:
  phone > checkin > manual > plan
Unfilled minutes inside the day's bounds are written as 'gap'.
"""

from __future__ import annotations

import argparse
from datetime import date, datetime, time, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from .db import SessionLocal

SOURCE_PRIORITY = {"phone": 0, "checkin": 1, "manual": 2, "plan": 3}


def _floor_minute(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)


def rebuild_day(db: Session, user_id: int, day: date) -> int:
    start = datetime.combine(day, time.min)
    end = start + timedelta(days=1)

    db.execute(
        text("DELETE FROM minutes WHERE user_id = :u AND ts >= :s AND ts < :e"),
        {"u": user_id, "s": start, "e": end},
    )

    rows = db.execute(
        text(
            """
            SELECT start_ts, end_ts, source, app, activity, category
            FROM blocks
            WHERE user_id = :u AND source <> 'plan'
              AND start_ts < :e AND end_ts > :s
            """
        ),
        {"u": user_id, "s": start, "e": end},
    ).mappings().all()

    # minute -> (priority, payload)
    filled: dict[datetime, tuple[int, dict]] = {}
    for r in rows:
        prio = SOURCE_PRIORITY.get(r["source"], 99)
        block_start = max(_floor_minute(r["start_ts"]), start)
        block_end = min(r["end_ts"], end)
        cur = block_start
        while cur < block_end:
            existing = filled.get(cur)
            if existing is None or prio < existing[0]:
                filled[cur] = (
                    prio,
                    {
                        "user_id": user_id,
                        "ts": cur,
                        "source": r["source"],
                        "app": r["app"],
                        "activity": r["activity"],
                        "category": r["category"],
                    },
                )
            cur += timedelta(minutes=1)

    now = datetime.utcnow()
    horizon = min(end, _floor_minute(now) + timedelta(minutes=1))
    cur = start
    rows_out: list[dict] = []
    while cur < horizon:
        payload = filled.get(cur)
        if payload:
            rows_out.append(payload[1])
        else:
            rows_out.append(
                {
                    "user_id": user_id,
                    "ts": cur,
                    "source": "gap",
                    "app": None,
                    "activity": None,
                    "category": None,
                }
            )
        cur += timedelta(minutes=1)

    if rows_out:
        db.execute(
            text(
                """
                INSERT INTO minutes
                  (user_id, ts, source, app, activity, category)
                VALUES
                  (:user_id, :ts, :source, :app, :activity, :category)
                """
            ),
            rows_out,
        )
    db.commit()
    return len(rows_out)


def rebuild_recent(hours: int = 3) -> None:
    """Rebuild the last `hours` hours across all users."""
    db = SessionLocal()
    try:
        user_ids = [int(r[0]) for r in db.execute(text("SELECT id FROM users"))]
        today = datetime.utcnow().date()
        for uid in user_ids:
            rebuild_day(db, uid, today)
            if datetime.utcnow().hour < hours:
                rebuild_day(db, uid, today - timedelta(days=1))
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", type=int, required=True)
    parser.add_argument("--date", type=str, default="today")
    args = parser.parse_args()

    day = (
        date.today()
        if args.date == "today"
        else datetime.strptime(args.date, "%Y-%m-%d").date()
    )
    db = SessionLocal()
    try:
        n = rebuild_day(db, args.user, day)
        print(f"wrote {n} minute rows for user={args.user} date={day}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
