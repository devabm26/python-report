"""
Database connection layer for the Thoughts Dashboard.

Implements:
  - Connection pooling (REQ-1: specs/architecture/database_layer.spec)
  - Context managers for lifecycle (REQ-2)
  - Centralised DatabaseConnection class (REQ-3)
  - Separation of concerns (REQ-4)
  - Type hints (REQ-5)
  - Error handling and logging (REQ-6)
  - Parameterised queries only (specs/security/sql_injection_prevention.spec)

Credentials are loaded exclusively from environment variables.
"""
import logging
from contextlib import contextmanager
from typing import Any, Generator, Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool

from src.config import Config

logger = logging.getLogger(__name__)


class DatabaseConnection:
    """Manages a psycopg2 connection pool and query execution."""

    def __init__(self) -> None:
        """Initialise the connection pool from environment-supplied config."""
        logger.info(
            "Initialising connection pool: host=%s db=%s min=%d max=%d",
            Config.DB_HOST,
            Config.DB_NAME,
            Config.DB_POOL_MIN,
            Config.DB_POOL_MAX,
        )
        try:
            self._pool: psycopg2.pool.SimpleConnectionPool = (
                psycopg2.pool.SimpleConnectionPool(
                    minconn=Config.DB_POOL_MIN,
                    maxconn=Config.DB_POOL_MAX,
                    host=Config.DB_HOST,
                    port=Config.DB_PORT,
                    dbname=Config.DB_NAME,
                    user=Config.DB_USER,
                    password=Config.DB_PASSWORD,
                    connect_timeout=Config.DB_TIMEOUT,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                )
            )
        except psycopg2.OperationalError as exc:
            # Do NOT log credentials – only log the host/db for diagnostics.
            logger.error(
                "Failed to create connection pool (host=%s db=%s): %s",
                Config.DB_HOST,
                Config.DB_NAME,
                exc,
            )
            raise

        logger.info("Connection pool initialised successfully")

    @contextmanager
    def get_connection(self) -> Generator[psycopg2.extensions.connection, None, None]:
        """
        Context manager that yields a connection from the pool and returns it
        when the block exits (even on exception).
        """
        conn: Optional[psycopg2.extensions.connection] = None
        try:
            conn = self._pool.getconn()
            logger.debug("Connection acquired from pool")
            yield conn
        except psycopg2.pool.PoolError as exc:
            logger.critical("Connection pool exhausted: %s", exc)
            raise
        finally:
            if conn is not None:
                self._pool.putconn(conn)
                logger.debug("Connection returned to pool")

    def execute_query(
        self,
        sql: str,
        params: Optional[tuple[Any, ...]] = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a SELECT query and return a list of row dicts.

        Args:
            sql:    Parameterised SQL query string (%s placeholders).
            params: Tuple of parameter values (never interpolated as strings).

        Returns:
            List of rows as dicts (column name → value).

        Raises:
            psycopg2.DatabaseError: On query execution failure.
        """
        with self.get_connection() as conn:
            try:
                with conn.cursor() as cursor:
                    logger.debug("Executing query (params redacted for security)")
                    cursor.execute(sql, params)
                    rows: list[dict[str, Any]] = [dict(row) for row in cursor.fetchall()]
                    logger.debug("Query returned %d rows", len(rows))
                    return rows
            except psycopg2.DatabaseError as exc:
                logger.error("Query execution failed: %s", exc)
                conn.rollback()
                raise

    def ping(self) -> bool:
        """Return True if the database is reachable, False otherwise."""
        try:
            self.execute_query("SELECT 1")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Database ping failed: %s", exc)
            return False

    def close(self) -> None:
        """Close all connections in the pool."""
        self._pool.closeall()
        logger.info("Connection pool closed")


# ---------------------------------------------------------------------------
# Domain query functions  (Layer 2 – separated from connection management)
# ---------------------------------------------------------------------------

ALLOWED_STATUSES = ("APPROVED", "REJECTED", "REMOVED", "IN_REVIEW")
ALLOWED_SORT_COLUMNS = ("content", "author", "status", "thumbs_up", "thumbs_down", "net_rating", "similarity_score")
ALLOWED_SORT_DIRS = ("ASC", "DESC")


def get_thoughts(
    db: DatabaseConnection,
    status_filter: Optional[str] = None,
    sort_by: str = "net_rating",
    sort_dir: str = "DESC",
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """
    Retrieve thoughts joined with their most recent evaluation score.

    All user-supplied filter/sort values are whitelisted before use.
    Pagination parameters are clamped to safe ranges.
    Parameterised query used for status filter — no string interpolation.

    Args:
        db:            DatabaseConnection instance.
        status_filter: One of ALLOWED_STATUSES or None for all.
        sort_by:       Column to sort on (whitelisted).
        sort_dir:      'ASC' or 'DESC' (whitelisted).
        limit:         Rows per page (clamped 1–500).
        offset:        Row offset (clamped ≥ 0).

    Returns:
        List of thought dicts including net_rating and similarity_score.
    """
    # Whitelist sort column and direction — these are interpolated as
    # SQL identifiers so they MUST be validated against a fixed set.
    if sort_by not in ALLOWED_SORT_COLUMNS:
        sort_by = "net_rating"
    if sort_dir.upper() not in ALLOWED_SORT_DIRS:
        sort_dir = "DESC"

    # Clamp pagination to safe ranges
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))

    # Build the WHERE clause with a parameterised placeholder
    where_clause = ""
    params: list[Any] = []

    if status_filter and status_filter.upper() in ALLOWED_STATUSES:
        where_clause = "WHERE t.status = %s"
        params.append(status_filter.upper())

    # Sort column and direction are NOT parameterisable in SQL (they are
    # identifiers/keywords, not values). We guard them with the whitelist above.
    sql = f"""
        SELECT
            t.id,
            t.content,
            t.author,
            t.status,
            t.thumbs_up,
            t.thumbs_down,
            (t.thumbs_up - t.thumbs_down) AS net_rating,
            te.similarity_score,
            t.created_at,
            t.updated_at
        FROM thoughts t
        LEFT JOIN LATERAL (
            SELECT similarity_score
            FROM thought_evaluations
            WHERE thought_id = t.id
            ORDER BY evaluated_at DESC
            LIMIT 1
        ) te ON true
        {where_clause}
        ORDER BY {sort_by} {sort_dir} NULLS LAST
        LIMIT %s OFFSET %s
    """
    params.extend([limit, offset])

    return db.execute_query(sql, tuple(params))


def get_thoughts_count(
    db: DatabaseConnection,
    status_filter: Optional[str] = None,
) -> int:
    """Return the total number of thoughts, optionally filtered by status."""
    where_clause = ""
    params: list[Any] = []

    if status_filter and status_filter.upper() in ALLOWED_STATUSES:
        where_clause = "WHERE status = %s"
        params.append(status_filter.upper())

    sql = f"SELECT COUNT(*) AS total FROM thoughts {where_clause}"
    rows = db.execute_query(sql, tuple(params) if params else None)
    return int(rows[0]["total"]) if rows else 0


def get_summary_stats(db: DatabaseConnection) -> dict[str, Any]:
    """Return per-status counts and overall totals."""
    sql = """
        SELECT
            status,
            COUNT(*) AS count
        FROM thoughts
        GROUP BY status
    """
    rows = db.execute_query(sql)
    stats: dict[str, Any] = {
        "APPROVED": 0,
        "REJECTED": 0,
        "REMOVED": 0,
        "IN_REVIEW": 0,
    }
    for row in rows:
        stats[row["status"]] = int(row["count"])
    stats["total"] = sum(stats.values())
    return stats
