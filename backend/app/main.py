from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from . import blocks as blocks_mod
from . import plan as plan_mod
from . import summary as summary_mod
from .auth import dev_login
from .config import Settings, get_settings
from .db import get_db, init_schema
from .merge import rebuild_recent


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema()
    scheduler = BackgroundScheduler()
    scheduler.add_job(rebuild_recent, "interval", minutes=5, id="merge-recent")
    scheduler.start()
    app.state.scheduler = scheduler
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(title="TimeGrid", version="0.1.0", lifespan=lifespan)
app.include_router(blocks_mod.router)
app.include_router(summary_mod.router)
app.include_router(plan_mod.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/auth/dev")
def dev_auth(
    apple_sub: str,
    tz: str = "UTC",
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    token = dev_login(apple_sub=apple_sub, tz=tz, settings=settings, db=db)
    return {"token": token}
