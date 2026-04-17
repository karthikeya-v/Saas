from sqlalchemy import text
from sqlalchemy.orm import Session

DEFAULT_CATEGORIES: dict[str, str] = {
    "instagram": "social",
    "tiktok": "social",
    "twitter": "social",
    "x": "social",
    "facebook": "social",
    "whatsapp": "messaging",
    "telegram": "messaging",
    "imessage": "messaging",
    "messages": "messaging",
    "gmail": "email",
    "mail": "email",
    "outlook": "email",
    "chrome": "browsing",
    "safari": "browsing",
    "firefox": "browsing",
    "youtube": "video",
    "netflix": "video",
    "spotify": "music",
    "podcasts": "audio",
    "slack": "work",
    "teams": "work",
    "xcode": "work",
    "vscode": "work",
    "notion": "work",
    "figma": "work",
    "duolingo": "learning",
    "kindle": "reading",
    "books": "reading",
    "maps": "commute",
    "uber": "commute",
    "strava": "exercise",
    "health": "exercise",
    "calm": "rest",
    "headspace": "rest",
}

TEXT_KEYWORDS: dict[str, str] = {
    "sleep": "sleep",
    "sleeping": "sleep",
    "meeting": "work",
    "call": "work",
    "standup": "work",
    "coding": "work",
    "writing": "work",
    "email": "email",
    "gym": "exercise",
    "run": "exercise",
    "running": "exercise",
    "walk": "exercise",
    "eat": "meal",
    "eating": "meal",
    "lunch": "meal",
    "dinner": "meal",
    "breakfast": "meal",
    "read": "reading",
    "reading": "reading",
    "cook": "chores",
    "clean": "chores",
    "commute": "commute",
    "drive": "commute",
}


def categorize(
    db: Session,
    user_id: int,
    app: str | None,
    activity: str | None,
) -> str | None:
    token = (app or activity or "").strip().lower()
    if not token:
        return None
    row = db.execute(
        text(
            "SELECT category FROM categories "
            "WHERE user_id = :u AND keyword = :k LIMIT 1"
        ),
        {"u": user_id, "k": token},
    ).first()
    if row:
        return str(row[0])
    if app:
        key = app.lower()
        for needle, cat in DEFAULT_CATEGORIES.items():
            if needle in key:
                return cat
    if activity:
        for word in activity.lower().split():
            if word in TEXT_KEYWORDS:
                return TEXT_KEYWORDS[word]
    return None
