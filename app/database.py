"""SQLite 存储层（标准库 sqlite3，线程安全封装）。"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).resolve().parent.parent / "data" / "detections.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id                    TEXT PRIMARY KEY,
    series_id             TEXT,
    created_at            TEXT NOT NULL,
    request_params        TEXT NOT NULL,
    result_json           TEXT NOT NULL,
    point_count           INTEGER NOT NULL,
    anomaly_segment_count INTEGER NOT NULL,
    anomaly_point_count   INTEGER NOT NULL,
    threshold             REAL NOT NULL,
    window_size           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detections_series_id ON detections(series_id);
CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections(created_at);

CREATE TABLE IF NOT EXISTS segment_statuses (
    detection_id  TEXT NOT NULL,
    segment_index INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',
    note          TEXT,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (detection_id, segment_index)
);
CREATE INDEX IF NOT EXISTS idx_segment_statuses_detection
    ON segment_statuses(detection_id);

CREATE TABLE IF NOT EXISTS counter_series (
    series_id      TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    max_counter         REAL,
    wrap_tolerance      REAL NOT NULL,
    max_gap_seconds     REAL,
    received_point_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS counter_readings (
    series_id  TEXT NOT NULL,
    ts_us      INTEGER NOT NULL,
    timestamp  TEXT NOT NULL,
    value      REAL NOT NULL,
    PRIMARY KEY (series_id, ts_us),
    FOREIGN KEY (series_id) REFERENCES counter_series(series_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_counter_readings_series_time
    ON counter_readings(series_id, ts_us);
"""


class CounterSeriesParameterConflict(Exception):
    """后续批次显式提交的回卷 / 断档参数与序列创建时不一致（409）。"""


class CounterReadingConflict(Exception):
    """同一时间戳已存在不同读数（或同批内同时间戳出现异值）（409）。"""


def _backfill_segment_statuses(conn: sqlite3.Connection) -> None:
    """为存量检测补写默认 open 的处置记录（幂等，可重复执行）。

    segment_statuses 表后于 detections 引入：升级已有数据库时，
    按 result_json 中的异常段数为每个历史段补一行 open 记录，
    updated_at 取检测的 created_at；已存在的行保持不变。
    """
    rows = conn.execute("SELECT id, created_at, result_json FROM detections").fetchall()
    for det_id, created_at, result_json in rows:
        segments = json.loads(result_json).get("segments", [])
        conn.executemany(
            """
            INSERT OR IGNORE INTO segment_statuses
                (detection_id, segment_index, status, note, updated_at)
            VALUES (?, ?, 'open', NULL, ?)
            """,
            [(det_id, idx, created_at) for idx in range(len(segments))],
        )


def init_db(db_path: str | None = None) -> None:
    """建库建表并启用 WAL；对存量检测回填默认处置记录。"""
    db_path = db_path or DB_PATH
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)
        _backfill_segment_statuses(conn)


@contextmanager
def get_conn(db_path: str | None = None) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path or DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def insert_detection(
    detection_id: str,
    series_id: str | None,
    request_params: dict[str, Any],
    result: dict[str, Any],
    db_path: str | None = None,
) -> str:
    created_at = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT INTO detections (
                id, series_id, created_at, request_params, result_json,
                point_count, anomaly_segment_count, anomaly_point_count,
                threshold, window_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                detection_id,
                series_id,
                created_at,
                json.dumps(request_params, ensure_ascii=False),
                json.dumps(result, ensure_ascii=False),
                result["point_count"],
                result["anomaly_segment_count"],
                result["anomaly_point_count"],
                result["threshold"],
                result["window_size"],
            ),
        )
        # 同一事务为每个异常段写入默认 open 处置记录（updated_at 取检测创建时间）
        conn.executemany(
            """
            INSERT INTO segment_statuses
                (detection_id, segment_index, status, note, updated_at)
            VALUES (?, ?, 'open', NULL, ?)
            """,
            [
                (detection_id, idx, created_at)
                for idx in range(len(result.get("segments", [])))
            ],
        )
    return created_at


def get_detection(detection_id: str, db_path: str | None = None) -> dict[str, Any] | None:
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM detections WHERE id = ?", (detection_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "series_id": row["series_id"],
        "created_at": row["created_at"],
        "request_params": json.loads(row["request_params"]),
        "result": json.loads(row["result_json"]),
    }


def get_segment_statuses(
    detection_id: str, db_path: str | None = None
) -> list[dict[str, Any]]:
    """按段序号升序返回一条检测全部异常段的处置记录（可能为空列表）。"""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT segment_index, status, note, updated_at
            FROM segment_statuses WHERE detection_id = ?
            ORDER BY segment_index
            """,
            (detection_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def transition_segment_status(
    detection_id: str,
    segment_index: int,
    target: str,
    note: str | None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """对单个异常段执行一次处置状态提交（读-判-写同一事务，BEGIN IMMEDIATE 防并发交错）。

    返回 ``{"outcome": ..., "record": {...}}``：

    - ``outcome="transition"``：合法前进一步，状态已推进，updated_at 刷新；
      请求带非空 note 时覆盖旧 note，否则保留；
    - ``outcome="idempotent"``：幂等重放（目标 == 当前），状态不变；
      仅当请求带非空 note 时更新 note 与 updated_at；
    - ``outcome="conflict"``：非法跳转，不做任何写入。

    调用方需先确认检测与段序号存在；记录缺失时抛 KeyError。
    """
    from . import segments as seg

    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path or DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                """
                SELECT status, note, updated_at FROM segment_statuses
                WHERE detection_id = ? AND segment_index = ?
                """,
                (detection_id, segment_index),
            ).fetchone()
            if row is None:
                raise KeyError(f"处置记录不存在: {detection_id}#{segment_index}")

            outcome = seg.decide(row["status"], target)
            if outcome == seg.OUTCOME_TRANSITION:
                new_note = note if note is not None else row["note"]
                conn.execute(
                    """
                    UPDATE segment_statuses
                    SET status = ?, note = ?, updated_at = ?
                    WHERE detection_id = ? AND segment_index = ?
                    """,
                    (target, new_note, now, detection_id, segment_index),
                )
                record = {"status": target, "note": new_note, "updated_at": now}
            elif outcome == seg.OUTCOME_IDEMPOTENT and note is not None:
                conn.execute(
                    """
                    UPDATE segment_statuses
                    SET note = ?, updated_at = ?
                    WHERE detection_id = ? AND segment_index = ?
                    """,
                    (note, now, detection_id, segment_index),
                )
                record = {"status": row["status"], "note": note, "updated_at": now}
            else:
                record = {
                    "status": row["status"],
                    "note": row["note"],
                    "updated_at": row["updated_at"],
                }
            conn.execute("COMMIT")
            return {"outcome": outcome, "record": record}
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def get_status_counts(
    detection_ids: list[str], db_path: str | None = None
) -> dict[str, dict[str, int]]:
    """批量统计各检测的异常段处置状态计数（无记录的检测不在返回中）。"""
    if not detection_ids:
        return {}
    placeholders = ",".join("?" for _ in detection_ids)
    with get_conn(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT detection_id, status, COUNT(*) AS cnt
            FROM segment_statuses
            WHERE detection_id IN ({placeholders})
            GROUP BY detection_id, status
            """,
            detection_ids,
        ).fetchall()
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = counts.setdefault(
            row["detection_id"], {"open": 0, "acknowledged": 0, "resolved": 0}
        )
        bucket[row["status"]] = row["cnt"]
    return counts


def list_detections(
    series_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db_path: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    with get_conn(db_path) as conn:
        if series_id is not None:
            total = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE series_id = ?", (series_id,)
            ).fetchone()[0]
            rows = conn.execute(
                """
                SELECT id, series_id, created_at, point_count,
                       anomaly_segment_count, anomaly_point_count,
                       threshold, window_size
                FROM detections WHERE series_id = ?
                ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (series_id, limit, offset),
            ).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            rows = conn.execute(
                """
                SELECT id, series_id, created_at, point_count,
                       anomaly_segment_count, anomaly_point_count,
                       threshold, window_size
                FROM detections ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
    items = [dict(r) for r in rows]
    counts = get_status_counts([item["id"] for item in items], db_path)
    for item in items:
        item["status_counts"] = counts.get(
            item["id"], {"open": 0, "acknowledged": 0, "resolved": 0}
        )
    return items, total


def _compute_counter_rates(
    readings: list[sqlite3.Row],
    *,
    max_counter: float | None,
    wrap_tolerance: float,
    max_gap_seconds: float | None,
    series_id: str,
) -> dict[str, Any]:
    """把已归档读数行交给无状态速率核心重算（延迟导入避免循环依赖）。"""
    from .counter_rates import compute_counter_rates

    timestamps = [row["timestamp"] for row in readings]
    values = [row["value"] for row in readings]
    return compute_counter_rates(
        timestamps,
        values,
        max_counter=max_counter,
        wrap_tolerance=wrap_tolerance,
        max_gap_seconds=max_gap_seconds,
        series_id=series_id,
    )


def upsert_counter_readings(
    series_id: str,
    parsed_points: list[tuple[int, str, float]],
    *,
    max_counter: float | None,
    wrap_tolerance: float,
    max_gap_seconds: float | None,
    explicit_params: set[str],
    db_path: str | None = None,
) -> dict[str, Any]:
    """在单个 SQLite 事务内分批合并计数器读数，提交后对全序列重算速率。

    ``parsed_points`` 为已解析的 ``(ts_us, canonical_timestamp, value)`` 列表。
    读-判-写全程在 ``BEGIN IMMEDIATE`` 事务中：任何冲突（参数不一致、批内异值、
    与已存同时间戳异值）都整体回滚并抛对应异常，不做部分写入。

    回卷 / 断档参数在首批创建序列时固定；后续批次中省略（不在
    ``explicit_params`` 内）的参数沿用已存值，显式提交但不一致抛
    :class:`CounterSeriesParameterConflict`。

    返回 ``{"rates": 最新全量速率结果, "submitted_point_count",
    "new_point_count", "duplicate_point_count", "received_point_count",
    "created_at", "updated_at"}``。
    """
    # 批内先按时间戳合并：同值记为幂等重复，异值直接冲突（不进入事务）
    batch_by_ts: dict[int, tuple[str, float]] = {}
    batch_duplicate = 0
    for ts_us, iso, value in parsed_points:
        existing = batch_by_ts.get(ts_us)
        if existing is None:
            batch_by_ts[ts_us] = (iso, value)
        elif existing[1] == value:
            batch_duplicate += 1
        else:
            raise CounterReadingConflict(
                f"本批在时间戳 {iso} 提交了两个不同读数: {existing[1]:g} 与 {value:g}"
            )

    conn = sqlite3.connect(db_path or DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM counter_series WHERE series_id = ?", (series_id,)
            ).fetchone()

            if row is None:
                eff_max_counter = max_counter
                eff_wrap_tolerance = wrap_tolerance
                eff_max_gap = max_gap_seconds
                created_at = datetime.now(timezone.utc).isoformat()
            else:
                eff_max_counter = row["max_counter"]
                eff_wrap_tolerance = row["wrap_tolerance"]
                eff_max_gap = row["max_gap_seconds"]
                created_at = row["created_at"]
                mismatches: list[str] = []
                if (
                    "max_counter" in explicit_params
                    and max_counter != eff_max_counter
                ):
                    mismatches.append(
                        f"max_counter: 提交 {max_counter!r}，已存 {eff_max_counter!r}"
                    )
                if (
                    "wrap_tolerance" in explicit_params
                    and wrap_tolerance != eff_wrap_tolerance
                ):
                    mismatches.append(
                        f"wrap_tolerance: 提交 {wrap_tolerance:g}，"
                        f"已存 {eff_wrap_tolerance:g}"
                    )
                if (
                    "max_gap_seconds" in explicit_params
                    and max_gap_seconds != eff_max_gap
                ):
                    mismatches.append(
                        f"max_gap_seconds: 提交 {max_gap_seconds!r}，"
                        f"已存 {eff_max_gap!r}"
                    )
                if mismatches:
                    raise CounterSeriesParameterConflict(
                        "回卷 / 断档参数与序列创建时不一致（参数在首批提交后固定，"
                        "省略则沿用已存值）：" + "；".join(mismatches)
                    )

            # 与已存读数逐个比对：同时间戳同值幂等、异值冲突
            new_rows: list[tuple[str, int, str, float]] = []
            existing_duplicate = 0
            if row is not None:
                placeholders = ",".join("?" for _ in batch_by_ts)
                old_rows = conn.execute(
                    f"""
                    SELECT ts_us, value FROM counter_readings
                    WHERE series_id = ? AND ts_us IN ({placeholders})
                    """,
                    (series_id, *batch_by_ts.keys()),
                ).fetchall()
                old_values = {r["ts_us"]: r["value"] for r in old_rows}
            else:
                old_values = {}
            for ts_us, (iso, value) in batch_by_ts.items():
                old_value = old_values.get(ts_us)
                if old_value is None:
                    new_rows.append((series_id, ts_us, iso, value))
                elif old_value == value:
                    existing_duplicate += 1
                else:
                    raise CounterReadingConflict(
                        f"时间戳 {iso} 已归档读数 {old_value:g}，"
                        f"本次提交 {value:g}，同时间戳不允许异值"
                    )

            updated_at = datetime.now(timezone.utc).isoformat()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO counter_series (
                        series_id, created_at, updated_at, max_counter,
                        wrap_tolerance, max_gap_seconds, received_point_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        series_id,
                        created_at,
                        updated_at,
                        eff_max_counter,
                        eff_wrap_tolerance,
                        eff_max_gap,
                        len(batch_by_ts),
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE counter_series
                    SET updated_at = ?, received_point_count = ?
                    WHERE series_id = ?
                    """,
                    (
                        updated_at,
                        row["received_point_count"] + len(new_rows),
                        series_id,
                    ),
                )
            conn.executemany(
                """
                INSERT INTO counter_readings (series_id, ts_us, timestamp, value)
                VALUES (?, ?, ?, ?)
                """,
                new_rows,
            )

            readings = conn.execute(
                """
                SELECT timestamp, value FROM counter_readings
                WHERE series_id = ? ORDER BY ts_us
                """,
                (series_id,),
            ).fetchall()
            rates = _compute_counter_rates(
                readings,
                max_counter=eff_max_counter,
                wrap_tolerance=eff_wrap_tolerance,
                max_gap_seconds=eff_max_gap,
                series_id=series_id,
            )
            received = len(readings)
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()

    return {
        "rates": rates,
        "submitted_point_count": len(parsed_points),
        "new_point_count": len(new_rows),
        "duplicate_point_count": batch_duplicate + existing_duplicate,
        "received_point_count": received,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def get_counter_series(
    series_id: str, db_path: str | None = None
) -> dict[str, Any] | None:
    """读取已归档计数器序列：元数据 + 全部读数按时间升序重算的最新结果。

    序列不存在时返回 ``None``。
    """
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM counter_series WHERE series_id = ?", (series_id,)
        ).fetchone()
        if row is None:
            return None
        readings = conn.execute(
            """
            SELECT timestamp, value FROM counter_readings
            WHERE series_id = ? ORDER BY ts_us
            """,
            (series_id,),
        ).fetchall()

    rates = _compute_counter_rates(
        readings,
        max_counter=row["max_counter"],
        wrap_tolerance=row["wrap_tolerance"],
        max_gap_seconds=row["max_gap_seconds"],
        series_id=series_id,
    )
    return {
        "rates": rates,
        "received_point_count": row["received_point_count"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
