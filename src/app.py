"""
Thoughts Dashboard - Flask application entry point.

Security controls implemented (see specs/security/web_security.spec):
  - REQ-1/REQ-2: Security headers on every response
  - REQ-3/REQ-4: Jinja2 auto-escaping enabled (default)
  - REQ-7/REQ-8: CSRF protection via Flask-WTF
  - REQ-10/REQ-11: Input validation with whitelisting
  - REQ-13/REQ-14: Secure session + SECRET_KEY from env
  - REQ-17/REQ-18: Generic error pages, no stack-trace leakage

Architecture: specs/architecture/web_application.spec
Database:     specs/architecture/database_layer.spec
"""
import logging
import logging.config
import os
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_wtf.csrf import CSRFProtect

# ---------------------------------------------------------------------------
# 1. Load environment variables (before anything else touches config)
# ---------------------------------------------------------------------------
load_dotenv()

try:
    from src.config import Config  # when run as: python -m src.app
    from src.database import (
        ALLOWED_STATUSES,
        DatabaseConnection,
        get_summary_stats,
        get_thoughts,
        get_thoughts_count,
    )
except ImportError:
    from config import Config  # type: ignore[no-redef]  # when run as: python src/app.py
    from database import (  # type: ignore[no-redef]
        ALLOWED_STATUSES,
        DatabaseConnection,
        get_summary_stats,
        get_thoughts,
        get_thoughts_count,
    )

# ---------------------------------------------------------------------------
# 2. Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if Config.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 3. Validate required configuration (fail fast)
# ---------------------------------------------------------------------------
Config.validate()

# ---------------------------------------------------------------------------
# 4. Initialise Flask
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")

# SECRET_KEY from environment — never hardcoded (REQ-14)
app.config["SECRET_KEY"] = Config.SECRET_KEY

# Secure session cookies (REQ-13)
app.config.update(
    SESSION_COOKIE_SECURE=not Config.DEBUG,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

# ---------------------------------------------------------------------------
# 5. CSRF protection (REQ-7)
# ---------------------------------------------------------------------------
csrf = CSRFProtect(app)

# ---------------------------------------------------------------------------
# 6. Database connection pool
# ---------------------------------------------------------------------------
db = DatabaseConnection()


@app.teardown_appcontext
def shutdown_db(_exc: Any) -> None:
    """Close pool on application shutdown."""
    pass  # pool lives for the lifetime of the process; closed via atexit


import atexit

atexit.register(db.close)

# ---------------------------------------------------------------------------
# 7. Security headers on every response (REQ-1 / REQ-2)
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response: Any) -> Any:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    if not Config.DEBUG:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# ---------------------------------------------------------------------------
# 8. Routes
# ---------------------------------------------------------------------------

@app.route("/health")
@csrf.exempt
def health() -> Any:
    """
    Health check endpoint for container orchestration.
    Exempt from CSRF (read-only, public — REQ-9).
    Returns 200 healthy / 503 unhealthy.
    """
    db_ok = db.ping()
    status = "healthy" if db_ok else "unhealthy"
    http_code = 200 if db_ok else 503
    return (
        jsonify(
            {
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checks": {"database": "ok" if db_ok else "failed"},
            }
        ),
        http_code,
    )


@app.route("/")
def index() -> Any:
    """
    Main dashboard — lists thoughts with pagination and status filter.

    Input validation (REQ-10 / REQ-11):
      - status:   whitelisted against ALLOWED_STATUSES
      - page:     validated as positive integer
      - per_page: validated as integer, clamped 1-500
      - sort_by:  whitelisted in database.get_thoughts()
      - sort_dir: whitelisted in database.get_thoughts()
    """
    # --- Input validation ---
    raw_status = request.args.get("status", "").strip().upper()
    status_filter = raw_status if raw_status in ALLOWED_STATUSES else None

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        logger.warning("Invalid page parameter from %s", request.remote_addr)
        page = 1

    try:
        per_page = max(1, min(int(request.args.get("per_page", Config.DEFAULT_PAGE_SIZE)), Config.MAX_PAGE_SIZE))
    except ValueError:
        logger.warning("Invalid per_page parameter from %s", request.remote_addr)
        per_page = Config.DEFAULT_PAGE_SIZE

    sort_by = request.args.get("sort_by", "net_rating").strip().lower()
    sort_dir = request.args.get("sort_dir", "DESC").strip().upper()

    offset = (page - 1) * per_page

    # --- Fetch data ---
    try:
        thoughts = get_thoughts(
            db,
            status_filter=status_filter,
            sort_by=sort_by,
            sort_dir=sort_dir,
            limit=per_page,
            offset=offset,
        )
        total = get_thoughts_count(db, status_filter=status_filter)
        summary = get_summary_stats(db)
    except Exception:
        logger.exception("Database error while fetching thoughts")
        return render_template("error.html", message="Unable to load data. Please try again later."), 500

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "index.html",
        thoughts=thoughts,
        summary=summary,
        # Pagination context
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        # Filter/sort context (passed back for UI state)
        status_filter=status_filter or "",
        sort_by=sort_by,
        sort_dir=sort_dir,
        # Valid statuses for filter dropdown
        statuses=[""] + list(ALLOWED_STATUSES),
    )


# ---------------------------------------------------------------------------
# 9. Error handlers (REQ-17 / REQ-18 — generic messages, no stack trace leak)
# ---------------------------------------------------------------------------

@app.errorhandler(400)
def bad_request(_error: Any) -> Any:
    logger.warning("400 Bad Request from %s %s", request.remote_addr, request.path)
    return render_template("error.html", message="Bad request."), 400


@app.errorhandler(404)
def not_found(_error: Any) -> Any:
    return render_template("error.html", message="Page not found."), 404


@app.errorhandler(500)
def internal_error(error: Any) -> Any:
    logger.error("500 Internal Server Error: %s", error)
    return render_template("error.html", message="An internal error occurred."), 500


# ---------------------------------------------------------------------------
# 10. Development entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
        debug=Config.DEBUG,
    )
