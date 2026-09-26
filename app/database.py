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
    series_id       TEXT PRIMARY KEY,
    max_counter     REAL,
    wrap_tolerance  REAL NOT NULL,
    max_gap_seconds REAL,
    point_count     INTEGER NOT NULL DEFAULT 0,
    result_json     TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS counter_points (
    series_id TEXT NOT NULL,
    ts_us     INTEGER NOT NULL,
    value     REAL NOT NULL,
    PRIMARY KEY (series_id, ts_us)
);
"""


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


class CounterSeriesParamMismatch(Exception):
    """归档序列已存在，且本次提交的回卷/断档参数与首次提交不一致（409）。"""


class CounterPointConflict(Exception):
    """提交批次中存在与已归档读数同时间戳异值的点（409，整批回滚）。"""


def ingest_counter_points(
    series_id: str,
    points: list[tuple[int, float]],
    *,
    max_counter: float | None,
    wrap_tolerance: float,
    max_gap_seconds: float | None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """把一批 ``(ts_us, value)`` 读数合并进归档序列并重算（读-判-写同一事务）。

    - 序列不存在时以本次提交的回卷/断档参数创建；已存在时提交参数必须与
      首次完全一致，否则抛 :class:`CounterSeriesParamMismatch`（不写入）；
    - 同时间戳同值（含批次内重复与已归档点）为幂等重复，计入
      ``duplicate_count``；同时间戳异值抛 :class:`CounterPointConflict`，
      整批回滚、不写入任何点；
    - 有新点接收时，对合并后的完整序列沿用持久化参数全量重算区间与 epoch
      （插入点两侧的受影响区间随之更新），结果写入 ``counter_series.result_json``；
      全部点均为幂等重复时不重算、不刷新 ``updated_at``（幂等重放无副作用）。
    """
    from .counter_rates import compute_counter_rates
    from .resampling import format_epoch_microseconds

    if not points:
        raise ValueError("points 不能为空")

    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path or DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM counter_series WHERE series_id = ?", (series_id,)
            ).fetchone()
            created = row is None
            if created:
                created_at = now
                stored_params = (max_counter, wrap_tolerance, max_gap_seconds)
            else:
                created_at = row["created_at"]
                stored_params = (
                    row["max_counter"],
                    row["wrap_tolerance"],
                    row["max_gap_seconds"],
                )
                submitted = (max_counter, wrap_tolerance, max_gap_seconds)
                if stored_params != submitted:
                    names = ("max_counter", "wrap_tolerance", "max_gap_seconds")
                    detail = "；".join(
                        f"{name}: 已归档={stored} 本次提交={sub}"
                        for name, stored, sub in zip(names, stored_params, submitted)
                        if stored != sub
                    )
                    raise CounterSeriesParamMismatch(
                        f"计数器序列 {series_id} 已存在，回卷/断档参数与首次提交不一致"
                        f"（{detail}）；归档序列的参数以首次提交为准"
                    )

            rows = conn.execute(
                """
                SELECT ts_us, value FROM counter_points
                WHERE series_id = ? ORDER BY ts_us
                """,
                (series_id,),
            ).fetchall()
            merged: dict[int, float] = {r["ts_us"]: r["value"] for r in rows}

            conflicts: list[tuple[int, float, float]] = []
            to_insert: list[tuple[str, int, float]] = []
            accepted = 0
            duplicates = 0
            for ts_us, value in points:
                if ts_us in merged:
                    if merged[ts_us] == value:
                        duplicates += 1
                    else:
                        conflicts.append((ts_us, merged[ts_us], value))
                    continue
                merged[ts_us] = value
                to_insert.append((series_id, ts_us, value))
                accepted += 1

            if conflicts:
                shown = "；".join(
                    f"{format_epoch_microseconds(ts)}: 已归档={old:g} 本次提交={new:g}"
                    for ts, old, new in conflicts[:10]
                )
                suffix = f" 等 {len(conflicts)} 处" if len(conflicts) > 10 else ""
                raise CounterPointConflict(
                    f"计数器序列 {series_id} 存在同时间戳异值读数{suffix}：{shown}；"
                    "同值重复为幂等，异值冲突整批回滚"
                )

            if accepted > 0:
                conn.executemany(
                    "INSERT INTO counter_points (series_id, ts_us, value) VALUES (?, ?, ?)",
                    to_insert,
                )
                ordered = sorted(merged.items())
                eff_max_counter, eff_wrap_tolerance, eff_max_gap = stored_params
                result = compute_counter_rates(
                    [format_epoch_microseconds(ts) for ts, _ in ordered],
                    [v for _, v in ordered],
                    max_counter=eff_max_counter,
                    wrap_tolerance=eff_wrap_tolerance,
                    max_gap_seconds=eff_max_gap,
                    series_id=series_id,
                )
                result_json = json.dumps(result, ensure_ascii=False)
                if created:
                    conn.execute(
                        """
                        INSERT INTO counter_series (
                            series_id, max_counter, wrap_tolerance, max_gap_seconds,
                            point_count, result_json, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            series_id,
                            max_counter,
                            wrap_tolerance,
                            max_gap_seconds,
                            result["point_count"],
                            result_json,
                            created_at,
                            now,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE counter_series
                        SET point_count = ?, result_json = ?, updated_at = ?
                        WHERE series_id = ?
                        """,
                        (result["point_count"], result_json, now, series_id),
                    )
                updated_at = now
            else:
                # 全部幂等重复：直接回读已存结果，不刷新 updated_at
                result = json.loads(row["result_json"])
                updated_at = row["updated_at"]

            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()

    return {
        "series_id": series_id,
        "created": created,
        "accepted_count": accepted,
        "duplicate_count": duplicates,
        "created_at": created_at,
        "updated_at": updated_at,
        "point_count": result["point_count"],
        "interval_count": result["interval_count"],
        "max_counter": result["max_counter"],
        "wrap_tolerance": result["wrap_tolerance"],
        "max_gap_seconds": result["max_gap_seconds"],
        "normal_count": result["normal_count"],
        "wrap_count": result["wrap_count"],
        "reset_count": result["reset_count"],
        "unknown_count": result["unknown_count"],
        "epoch_count": result["epoch_count"],
        "total_delta": result["total_delta"],
        "total_duration_seconds": result["total_duration_seconds"],
        "rate_per_second": result["rate_per_second"],
    }


def get_counter_series(
    series_id: str, db_path: str | None = None
) -> dict[str, Any] | None:
    """按 series_id 读取归档序列的最新计算结果；不存在返回 None。"""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM counter_series WHERE series_id = ?", (series_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        "series_id": row["series_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "result": json.loads(row["result_json"]),
    }
