"""lock_manager.py -- Redis distributed lock, real Lua execution via
fakeredis (see conftest.py's autouse _fake_redis fixture), including the
ABA race a naive DEL would get wrong."""
import lock_manager


def test_acquire_returns_a_token():
    token = lock_manager.acquire_lock(asset_id=1)
    assert token is not None


def test_second_acquire_on_locked_asset_is_non_blocking_and_fails():
    lock_manager.acquire_lock(asset_id=1)
    assert lock_manager.acquire_lock(asset_id=1) is None


def test_different_assets_lock_independently():
    token1 = lock_manager.acquire_lock(asset_id=1)
    token2 = lock_manager.acquire_lock(asset_id=2)
    assert token1 is not None
    assert token2 is not None


def test_release_with_wrong_token_is_rejected():
    token = lock_manager.acquire_lock(asset_id=1)
    assert lock_manager.release_lock(1, "not-the-real-token") is False
    assert lock_manager.is_locked(1) is True
    lock_manager.release_lock(1, token)  # cleanup


def test_release_with_correct_token_succeeds():
    token = lock_manager.acquire_lock(asset_id=1)
    assert lock_manager.release_lock(1, token) is True
    assert lock_manager.is_locked(1) is False


def test_reacquire_after_release_gets_a_fresh_token():
    token1 = lock_manager.acquire_lock(asset_id=1)
    lock_manager.release_lock(1, token1)
    token2 = lock_manager.acquire_lock(asset_id=1)
    assert token2 is not None
    assert token2 != token1


def test_aba_race_stale_token_cannot_release_a_new_holders_lock():
    """The core correctness property: a worker whose lock already
    expired (or who's just wrong) must never be able to delete a
    DIFFERENT worker's currently-active lock on the same asset."""
    token1 = lock_manager.acquire_lock(asset_id=1)
    lock_manager.release_lock(1, token1)
    new_token = lock_manager.acquire_lock(asset_id=1)

    stale_release_succeeded = lock_manager.release_lock(1, "some-other-stale-token")

    assert stale_release_succeeded is False
    assert lock_manager.is_locked(1) is True


def test_renew_only_works_for_the_correct_token_holder():
    token = lock_manager.acquire_lock(asset_id=1)
    assert lock_manager.renew_lock(1, token, ttl=100) is True
    assert lock_manager.renew_lock(1, "wrong-token", ttl=100) is False
