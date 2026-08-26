"""
Distributed lock manager.

Orchestration engine doc §13 (Distributed Lock Management): "Multiple jobs
may attempt to scan the same target... Running both simultaneously may
trigger security controls, produce inaccurate results, or violate PCI
scanning rules." Solution: one Redis lock per asset, `lock:asset:<id>`,
acquired with `SET key value NX EX ttl`.

§15 (Deadlock Prevention Strategy) is implemented as follows:
  - Strategy 1 (Single Target Lock): one key per asset -- see acquire_lock.
  - Strategy 2 (Ordered Lock Acquisition): doesn't apply here -- each
    ScanJob only ever needs exactly one asset's lock, never two at once,
    so there's no multi-lock ordering to get wrong.
  - Strategy 3 (Non-Blocking Lock): acquire_lock never blocks/waits: it
    either returns a token immediately or returns None immediately. The
    caller (scheduler_tick in tasks.py) is responsible for requeuing with
    backoff, not this module.
  - Strategy 4 (TTL Expiration): every lock has a TTL. If the worker
    holding it crashes without releasing, the lock self-expires and the
    job becomes retryable again -- this is the crash-safety net, not the
    primary release path (see release_lock).

release_lock uses a compare-and-delete Lua script rather than a plain
DEL: without that, a worker whose lock already expired (e.g. it ran
long) could delete a *different* worker's lock that has since acquired
the same key -- an ABA-style bug. The token makes release safe even
across that race.
"""

import uuid
import redis
from config import Config

_redis_client = None

# §13 example: "TTL = 2 hours". Long enough to cover the slowest realistic
# pipeline (Nmap's full -p- scan alone can run 20-30+ minutes; OpenVAS
# polling adds more) without leaving a genuinely dead lock around for too
# long if a worker crashes.
DEFAULT_LOCK_TTL_SECONDS = 7200


def _get_redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(Config.CELERY_BROKER_URL, decode_responses=True)
    return _redis_client


def _lock_key(asset_id):
    return f"lock:asset:{asset_id}"


def acquire_lock(asset_id, ttl=DEFAULT_LOCK_TTL_SECONDS):
    """Non-blocking. Returns a token (str) if the lock was acquired, or
    None if another job currently holds it. The token must be passed back
    to release_lock/renew_lock -- it's what makes those safe against the
    expired-then-reacquired race described in the module docstring.
    """
    token = uuid.uuid4().hex
    acquired = _get_redis().set(_lock_key(asset_id), token, nx=True, ex=ttl)
    return token if acquired else None


_RELEASE_LUA = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"""

_RENEW_LUA = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("EXPIRE", KEYS[1], ARGV[2])
else
    return 0
end
"""


def release_lock(asset_id, token):
    """Compare-and-delete: only removes the lock if `token` still matches
    what's stored, so a job can never accidentally release a lock it no
    longer actually holds. Returns True if it actually released the lock.
    """
    if not token:
        return False
    result = _get_redis().eval(_RELEASE_LUA, 1, _lock_key(asset_id), token)
    return bool(result)


def renew_lock(asset_id, token, ttl=DEFAULT_LOCK_TTL_SECONDS):
    """Heartbeat-style TTL extension for a long-running job, only if we
    still hold the lock. Not currently called anywhere by default (the
    static 2-hour TTL comfortably covers the pipeline), but available for
    a future long-scan case without needing lock-manager changes.
    """
    result = _get_redis().eval(_RENEW_LUA, 1, _lock_key(asset_id), token, ttl)
    return bool(result)


def is_locked(asset_id):
    return _get_redis().exists(_lock_key(asset_id)) > 0
