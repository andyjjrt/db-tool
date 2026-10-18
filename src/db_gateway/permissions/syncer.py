"""Replay the permission change stream independently for each target database."""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from typing import TypedDict

import aiosqlite

from db_gateway import metadata
from db_gateway.metadata import audit
from db_gateway.permissions.context import ConnectionLocks, load_connections, mapping_context
from db_gateway.permissions.executor import ApplyError
from db_gateway.permissions.executor_protocol import Executor
from db_gateway.permissions.mapping import grant_ops, revoke_ops
from db_gateway.permissions.store import (
    ChangeOp,
    ContinuationTokenInvalid,
    PermissionStore,
    PermissionStoreUnavailable,
    Tuple,
)
from db_gateway.permissions.types import DropGroupRole, PgOp, RevokeMembership

logger = logging.getLogger(__name__)


class SyncStatus(TypedDict):
    connection: str
    continuation_token: str | None
    last_applied_at: str | None
    last_error: str | None
    fail_count: int


class Syncer:
    def __init__(
        self,
        db: aiosqlite.Connection,
        store: PermissionStore,
        executor: Executor,
        locks: ConnectionLocks,
        *,
        fga_store_id: str,
        poll_interval_s: float,
        full_reconcile: Callable[[str], Awaitable[object]],
        max_backoff_s: float = 60,
    ) -> None:
        """Build a consumer with a strict ``full_reconcile(connection)`` callback.

        The callback must raise on ANY failure, including failed repairs
        reported by a reconciler. It acquires ConnectionLocks itself. Recovery
        checkpoints only after it returns successfully; W5 must pass
        ``Reconciler.reconcile_strict``, not the report-returning ``reconcile``.
        """
        if poll_interval_s <= 0 or max_backoff_s <= 0:
            raise ValueError("poll interval and maximum backoff must be positive")
        self._db = db
        self._store = store
        self._executor = executor
        self._locks = locks
        self._store_id = fga_store_id
        self._poll_interval = poll_interval_s
        self._max_backoff = max_backoff_s
        self._full_reconcile = full_reconcile
        self._stopping = asyncio.Event()
        self._workers: dict[str, asyncio.Task[None]] = {}
        self._worker_failures: dict[str, int] = {}
        self._round_locks: dict[str, asyncio.Lock] = {}
        self._inline_tasks: set[asyncio.Task[bool]] = set()

    async def _state(self, connection: str) -> SyncStatus:
        consumer = f"pg:{connection}"
        async with metadata.transaction(self._db):
            await self._db.execute(
                "INSERT INTO sync_state (consumer, fga_store_id) VALUES (?, ?) "
                "ON CONFLICT(consumer) DO NOTHING",
                (consumer, self._store_id),
            )
        async with self._db.execute(
            "SELECT continuation_token, last_applied_at, last_error, fail_count "
            "FROM sync_state WHERE consumer = ?",
            (consumer,),
        ) as cursor:
            row = await cursor.fetchone()
        assert row is not None
        return SyncStatus(
            connection=connection,
            continuation_token=row[0],
            last_applied_at=row[1],
            last_error=row[2],
            fail_count=row[3],
        )

    async def status(self) -> list[SyncStatus]:
        return [await self._state(info.name) for info in await load_connections(self._db)]

    async def _checkpoint(
        self,
        connection: str,
        token: str,
        *,
        poison: Sequence[tuple[Tuple, ValueError]] = (),
    ) -> None:
        async with metadata.transaction(self._db):
            for item, exc in poison:
                error = f"{type(exc).__name__}: {exc}"
                logger.error("Skipping permission change on %s: %s", connection, error)
                await audit.record(
                    self._db,
                    "sync",
                    error=error,
                    detail={"connection": connection, "source": "stream", "tuple": asdict(item)},
                )
            await self._db.execute(
                "UPDATE sync_state SET fga_store_id = ?, continuation_token = ?, "
                "last_applied_at = ?, last_error = NULL, fail_count = 0 WHERE consumer = ?",
                (self._store_id, token, metadata.now_iso(), f"pg:{connection}"),
            )

    async def _error(
        self,
        connection: str | None,
        exc: Exception,
        *,
        source: str = "stream",
    ) -> None:
        error = f"{type(exc).__name__}: {exc}"
        if (
            isinstance(exc, ApplyError)
            and isinstance(exc.op, RevokeMembership)
            and "permission denied to revoke privileges granted by role" in str(exc.original)
        ):
            error += "; an operator must revoke this membership with a superuser"
        logger.error("Permission sync on %s: %s", connection, error)
        async with metadata.transaction(self._db):
            if source == "stream":
                await self._db.execute(
                    "UPDATE sync_state SET last_error = ?, fail_count = fail_count + 1 "
                    "WHERE consumer = ?",
                    (error, f"pg:{connection}"),
                )
            await audit.record(
                self._db,
                "sync",
                error=error,
                detail={
                    "connection": connection,
                    "source": source,
                },
            )

    async def _recover(self, connection: str) -> None:
        token = None
        while True:
            page = await self._store.read_changes(token)
            token = page.continuation_token
            if not page.changes:
                break
            if self._stopping.is_set():
                return
        # The callback takes ConnectionLocks itself, like a normal full reconcile.
        await self._full_reconcile(connection)
        async with self._locks(connection):
            await self._checkpoint(connection, token)

    async def sync_once(self, connection: str) -> None:
        """Drain available pages; failures remain visible and are retried next round."""
        async with self._round_locks.setdefault(connection, asyncio.Lock()):
            state = await self._state(connection)
            token = state["continuation_token"]
            try:
                async with self._db.execute(
                    "SELECT fga_store_id FROM sync_state WHERE consumer = ?",
                    (f"pg:{connection}",),
                ) as cursor:
                    row = await cursor.fetchone()
                assert row is not None
                if row[0] != self._store_id:
                    # Retain the old identity/token until reconciliation succeeds,
                    # so failure (or restart) cannot lose the pending store reset.
                    await self._recover(connection)
                    return
                while True:
                    connections = await load_connections(self._db)
                    if connection not in {info.name for info in connections}:
                        return
                    ctx = mapping_context(connections)
                    async with self._locks(connection):
                        page = await self._store.read_changes(token)
                        if not page.changes and page.continuation_token == (token or ""):
                            if state["fail_count"]:
                                async with metadata.transaction(self._db):
                                    await self._db.execute(
                                        "UPDATE sync_state SET last_error = NULL, fail_count = 0 "
                                        "WHERE consumer = ?",
                                        (f"pg:{connection}",),
                                    )
                            return
                        poison: list[tuple[Tuple, ValueError]] = []
                        for change in page.changes:
                            try:
                                targets = (
                                    grant_ops(change.tuple, ctx)
                                    if change.op is ChangeOp.WRITE
                                    else revoke_ops(change.tuple, ctx)
                                )
                            except ValueError as exc:
                                poison.append((change.tuple, exc))
                                continue
                            ops = [
                                target.op for target in targets if target.connection == connection
                            ]
                            if ops:
                                await self._executor.apply(connection, ops)
                        if poison:
                            await self._checkpoint(
                                connection, page.continuation_token, poison=poison
                            )
                        else:
                            await self._checkpoint(connection, page.continuation_token)
                        state["fail_count"] = 0
                    token = page.continuation_token
                    if not page.changes or self._stopping.is_set():
                        return
            except ContinuationTokenInvalid:
                try:
                    await self._recover(connection)
                except Exception as exc:
                    await self._error(connection, exc)
            except Exception as exc:
                await self._error(connection, exc)

    def _backoff(self, fail_count: int) -> float:
        delay = min(self._poll_interval, self._max_backoff)
        for _ in range(fail_count):
            delay = min(delay * 2, self._max_backoff)
            if delay == self._max_backoff:
                break
        return delay

    async def _pause(self, delay: float) -> None:
        try:
            await asyncio.wait_for(self._stopping.wait(), delay)
        except TimeoutError:
            pass

    async def _consume(self, connection: str) -> None:
        while not self._stopping.is_set():
            if connection not in {info.name for info in await load_connections(self._db)}:
                return
            await self.sync_once(connection)
            state = await self._state(connection)
            self._worker_failures[connection] = 0
            await self._pause(self._backoff(state["fail_count"]))

    async def _restart_consumer(self, connection: str, failures: int) -> None:
        await self._pause(self._backoff(failures))
        if not self._stopping.is_set():
            await self._consume(connection)

    async def run(self) -> None:
        """Run as a lifespan task; discover connections without waiting on their PG work."""
        try:
            while not self._stopping.is_set():
                for info in await load_connections(self._db):
                    worker = self._workers.get(info.name)
                    if worker is None or worker.done():
                        failures = 0
                        if worker is not None:
                            exc = (
                                asyncio.CancelledError()
                                if worker.cancelled()
                                else worker.exception()
                            )
                            if exc is not None:
                                logger.error(
                                    "Permission consumer %s died; restarting with backoff: %s",
                                    info.name,
                                    exc,
                                )
                                failures = self._worker_failures.get(info.name, 0) + 1
                                self._worker_failures[info.name] = failures
                        self._workers[info.name] = asyncio.create_task(
                            self._restart_consumer(info.name, failures)
                            if failures
                            else self._consume(info.name),
                            name=f"pg:{info.name}",
                        )
                await self._pause(self._poll_interval)
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Finish in-flight transactions rather than canceling their tasks."""
        self._stopping.set()
        results = await asyncio.gather(
            *self._workers.values(), *self._inline_tasks, return_exceptions=True
        )
        for result in results:
            if isinstance(result, BaseException):
                logger.error("Permission task failed during shutdown: %s", result)

    async def _apply_inline(self, deletes: Sequence[Tuple], queued: asyncio.Event) -> bool:
        async def apply(
            connection: str, items: dict[Tuple, list[PgOp]], started: asyncio.Event
        ) -> bool:
            # No suspension between this signal and acquiring/queuing on the lock.
            started.set()
            try:
                async with self._locks(connection):
                    ops: list[PgOp] = []
                    for item, revoked in items.items():
                        try:
                            if item in await self._store.read(
                                item.object, item.relation, item.user
                            ):
                                continue
                        except PermissionStoreUnavailable as exc:
                            # The delete succeeded earlier: fail closed if its
                            # fresh state cannot be checked.
                            await self._error(connection, exc, source="inline")
                        ops.extend(revoked)
                    revokes = [op for op in ops if not isinstance(op, DropGroupRole)]
                    drops = [op for op in ops if isinstance(op, DropGroupRole)]
                    if revokes:
                        await self._executor.apply(connection, revokes)
                    if drops:
                        # A dependent role must not roll back fast membership revocation.
                        await self._executor.apply(connection, drops)
                return True
            except Exception as exc:
                await self._error(connection, exc, source="inline")
                return False

        try:
            ctx = mapping_context(await load_connections(self._db))
            grouped: dict[str, dict[Tuple, list[PgOp]]] = {}
            for item in deletes:
                for target in revoke_ops(item, ctx):
                    grouped.setdefault(target.connection, {}).setdefault(item, []).append(target.op)
            tasks: list[asyncio.Task[bool]] = []
            started: list[asyncio.Event] = []
            for connection, ops in grouped.items():
                ready = asyncio.Event()
                started.append(ready)
                tasks.append(asyncio.create_task(apply(connection, ops, ready)))
            await asyncio.gather(*(ready.wait() for ready in started))
            queued.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    logger.error("Inline permission revoke task failed: %s", result)
            return all(result is True for result in results)
        except Exception as exc:
            await self._error(None, exc, source="inline")
            return False
        finally:
            queued.set()

    def _inline_done(self, task: asyncio.Task[bool]) -> None:
        self._inline_tasks.discard(task)
        if task.cancelled():
            logger.warning("Inline permission revoke was canceled")
        elif exc := task.exception():
            logger.error("Inline permission revoke failed: %s", exc)
        else:
            logger.info("Inline permission revoke completed: synced=%s", task.result())

    async def apply_inline(self, deletes: Sequence[Tuple], timeout_s: float) -> bool:
        queued = asyncio.Event()
        task = asyncio.create_task(self._apply_inline(deletes, queued))
        self._inline_tasks.add(task)
        task.add_done_callback(self._inline_done)
        # Keep RuleService's global lock until every connection revoke is queued,
        # including when the timeout is zero. PG work remains shielded throughout.
        await queued.wait()
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout_s)
        except TimeoutError:
            return False
        except Exception:
            logger.exception("Inline permission revoke failed")
            return False
