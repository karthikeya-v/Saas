from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import current_user_id
from .categorize import categorize
from .db import get_db
from .models import BlockIn, BlockOut, BlocksBatch

router = APIRouter(prefix="/v1", tags=["blocks"])


@router.post("/blocks", status_code=202)
def upsert_blocks(
    batch: BlocksBatch,
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> dict[str, int]:
    if not batch.blocks:
        return {"accepted": 0}
    for b in batch.blocks:
        if b.end_ts <= b.start_ts:
            raise HTTPException(400, detail=f"end_ts <= start_ts for {b.client_id}")
        cat = b.category or categorize(db, user_id, b.app, b.activity)
        db.execute(
            text(
                """
                INSERT INTO blocks
                  (user_id, start_ts, end_ts, source, app, activity, category, client_id)
                VALUES
                  (:user_id, :start_ts, :end_ts, :source, :app, :activity, :category, :client_id)
                ON DUPLICATE KEY UPDATE
                  start_ts = VALUES(start_ts),
                  end_ts   = VALUES(end_ts),
                  source   = VALUES(source),
                  app      = VALUES(app),
                  activity = VALUES(activity),
                  category = VALUES(category)
                """
            ),
            {
                "user_id": user_id,
                "start_ts": b.start_ts,
                "end_ts": b.end_ts,
                "source": b.source,
                "app": b.app,
                "activity": b.activity,
                "category": cat,
                "client_id": b.client_id,
            },
        )
    db.commit()
    return {"accepted": len(batch.blocks)}


@router.get("/blocks", response_model=list[BlockOut])
def list_blocks(
    from_: datetime = Query(alias="from"),
    to: datetime = Query(...),
    user_id: int = Depends(current_user_id),
    db: Session = Depends(get_db),
) -> list[BlockOut]:
    rows = db.execute(
        text(
            """
            SELECT id, client_id, start_ts, end_ts, source, app, activity, category
            FROM blocks
            WHERE user_id = :u AND start_ts < :to AND end_ts > :from_
            ORDER BY start_ts
            """
        ),
        {"u": user_id, "from_": from_, "to": to},
    ).mappings().all()
    return [BlockOut(**dict(r)) for r in rows]
