"""四条安全修复要求的属性测试 + 模块级函数组合测试。

固定时间戳与固定密钥，确保测试确定性；与既有的契约测试并存。
"""

import time

import pytest

from security import totp_replay_window as mod

# RFC 4648 Base32，解码后 20 字节（160 bit），满足密钥强度要求
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
T0 = 1_700_000_000  # 固定基准时刻，避免依赖系统时钟


def code_at(offset, timestamp=T0):
    return mod.generate_totp(SECRET, timestamp=timestamp, offset=offset)


# ---- 要求 1：窗口收窄到 ±1 步 ----------------------------------------------

class TestWindowOneStep:
    def test_window_helper_accepts_only_plus_minus_one(self):
        assert mod.window_one_step(100, 100) is True
        assert mod.window_one_step(100, 99) is True
        assert mod.window_one_step(100, 101) is True
        assert mod.window_one_step(100, 98) is False
        assert mod.window_one_step(100, 102) is False
        # 旧实现的 ±10 步越窗点必须被结构性拒绝
        assert mod.window_one_step(100, 110) is False
        assert mod.window_one_step(100, 90) is False

    def test_current_and_neighbor_codes_pass(self):
        for offset in (-1, 0, 1):
            result = mod.validation(code_at(offset), SECRET, timestamp=T0)
            assert result["ok"] is True

    def test_codes_beyond_one_step_are_rejected_even_though_correct(self):
        # ±2 到 ±10 步的码本身是合法 TOTP，但超出窗口必须拒绝
        for offset in (-10, -5, -2, 2, 5, 10):
            result = mod.validation(code_at(offset), SECRET, timestamp=T0)
            assert result["ok"] is False
            assert result["reason"] in ("invalid_code", "calibration_required")


# ---- 要求 2：用过即写入已消费集合，窗口内不可重放 -----------------------------

class TestConsumedSet:
    def test_same_code_replay_is_rejected(self):
        first = mod.validation(code_at(0), SECRET, timestamp=T0)
        assert first["ok"] is True
        # 同一时刻、同一码再次提交 → 重放拒绝
        replay = mod.validation(
            code_at(0), SECRET, timestamp=T0, consumed=first["consumed"])
        assert replay["ok"] is False
        assert replay["reason"] == "replay"

    def test_consumed_set_helper_records_and_flags_key(self):
        consumed, store = mod.consumed_set({}, ("user", 42), expiry=99)
        assert consumed is False
        again, store2 = mod.consumed_set(store, ("user", 42))
        assert again is True
        assert store2 == store

    def test_replay_guard_rejects_second_submission(self):
        decision = mod.replay_guard({}, ("user", 1), expiry=99)
        assert decision["allowed"] is True
        decision2 = mod.replay_guard(decision["store"], ("user", 1))
        assert decision2["allowed"] is False
        assert decision2["reason"] == "replay"

    def test_different_counters_are_distinct_consumed_keys(self):
        first = mod.validation(code_at(0), SECRET, timestamp=T0)
        # 相邻时间步的新码不受上一条已消费记录影响
        neighbor = mod.validation(
            code_at(1), SECRET, timestamp=T0, consumed=first["consumed"])
        assert neighbor["ok"] is True

    def test_purge_expired_removes_stale_entries(self):
        entries = {("u", 1): 100, ("u", 2): 300}
        assert mod.purge_expired(entries, 200) == {("u", 2): 300}
        assert mod.purge_expired(entries, 300) == {}

    def test_stateful_validator_blocks_replay_within_window(self):
        v = mod.TOTPValidator(SECRET)
        assert v.verify(code_at(0), now=T0)["ok"] is True
        result = v.verify(code_at(0), now=T0)
        assert result["ok"] is False
        assert result["reason"] == "replay"


# ---- 要求 3：时钟漂移检测与校准提示 ------------------------------------------

class TestClockDrift:
    def test_drift_within_tolerance_does_not_require_calibration(self):
        info = mod.clock_drift(101, 100)
        assert info["drift_steps"] == 1
        assert info["within_tolerance"] is True
        assert info["calibration_required"] is False

    def test_drift_beyond_tolerance_requires_calibration(self):
        info = mod.clock_drift(110, 100)
        assert info["drift_steps"] == 10
        assert info["calibration_required"] is True

    def test_far_drift_code_is_detected_and_rejected_with_calibration_hint(self):
        # 设备快了 3 个时间步：码正确但越窗，拒绝并要求校准，不得静默放行
        result = mod.validation(code_at(3), SECRET, timestamp=T0)
        assert result["ok"] is False
        assert result["reason"] == "calibration_required"
        assert result["drift"]["calibration_required"] is True
        assert "校准" in result["message"]

    def test_resync_only_compensates_within_one_step(self):
        assert mod.resync(0) == 0
        assert mod.resync(1) == 1
        assert mod.resync(-1) == -1
        assert mod.resync(2) is None
        assert mod.resync(-10) is None

    def test_validator_adopts_offset_after_repeated_same_direction_drift(self):
        v = mod.TOTPValidator(SECRET)
        base = T0 - (T0 % mod.DEFAULT_STEP)  # 对齐时间步边界
        # 连续两次使用“上一步”的码（模拟设备慢 1 步）
        r1 = v.verify(mod.generate_totp(SECRET, timestamp=base, offset=-1), now=base)
        r2 = v.verify(
            mod.generate_totp(SECRET, timestamp=base + mod.DEFAULT_STEP, offset=-1),
            now=base + mod.DEFAULT_STEP,
        )
        assert r1["ok"] and r2["ok"]
        assert v.drift_offset == -1
        assert v.calibration_suggested is True
        assert any(e["event"] == "clock_resync" for e in v.audit_log.records)


# ---- 要求 4：备份码一次性作废 ------------------------------------------------

class TestBackupCodeOnce:
    def test_backup_code_succeeds_then_is_invalidated(self):
        digest = mod.hash_backup_code("1234-5678")
        ok, remaining = mod.backup_code_once({digest}, "1234-5678")
        assert ok is True
        assert digest not in remaining
        ok2, remaining2 = mod.backup_code_once(remaining, "1234-5678")
        assert ok2 is False
        assert remaining2 == frozenset()

    def test_unknown_backup_code_does_not_mutate_store(self):
        digest = mod.hash_backup_code("aaaa-bbbb")
        ok, remaining = mod.backup_code_once({digest}, "0000-0000")
        assert ok is False
        assert remaining == frozenset({digest})

    def test_backup_codes_are_stored_only_as_hashes(self):
        v = mod.TOTPValidator(SECRET)
        v.provision_backup_codes(["9999-0000", "1111-2222"])
        assert "9999-0000" not in v.backup_hashes
        assert all(len(h) == 64 for h in v.backup_hashes)  # SHA-256 hex 长度
        first = v.recover("9999-0000", now=T0)
        assert first["ok"] is True
        # 同一备份码二次使用必须失败
        second = v.recover("9999-0000", now=T0)
        assert second["ok"] is False
        assert second["reason"] == "backup_consumed"

    def test_backup_code_path_in_main_validation_is_single_use(self):
        digest = mod.hash_backup_code("4444-3333")
        first = mod.validation(
            "4444-3333", SECRET, timestamp=T0, backup_hashes={digest})
        assert first["ok"] is True
        second = mod.validation(
            "4444-3333", SECRET, timestamp=T0,
            backup_hashes=first["backup_hashes"])
        assert second["ok"] is False


# ---- 配套机制 ----------------------------------------------------------------

class TestSupportingMechanisms:
    def test_time_step_uses_floor_division(self):
        assert mod.time_step(60, 30) == 2
        assert mod.time_step(59, 30) == 1

    def test_hmac_compare_is_constant_time_and_type_tolerant(self):
        assert mod.hmac_compare("abc", "abc") is True
        assert mod.hmac_compare(b"abc", b"abc") is True
        assert mod.hmac_compare(123, 123) is True
        assert mod.hmac_compare("abc", "abd") is False

    def test_secret_length_enforces_160_bit_minimum(self):
        assert mod.secret_length(SECRET) is True
        assert mod.secret_length("short") is False
        # 20 字节密钥满足 16 字节最低要求，但不满足 32 字节要求
        assert mod.secret_length(SECRET, minimum=16) is True
        assert mod.secret_length(SECRET, minimum=32) is False

    def test_rate_limit_locks_after_threshold(self):
        assert mod.rate_limit(4, 5) is True
        assert mod.rate_limit(5, 5) is False

    def test_rate_limiter_stateful_lockout(self):
        rl = mod.RateLimiter(max_attempts=3, window=300)
        for _ in range(3):
            rl.record_failure(T0)
        assert rl.allowed(T0) is False
        # 窗口过后自动解锁
        assert rl.allowed(T0 + 301) is True

    def test_validation_respects_rate_limit_even_with_correct_code(self):
        result = mod.validation(
            code_at(0), SECRET, timestamp=T0, attempts=5, max_attempts=5)
        assert result["ok"] is False
        assert result["reason"] == "rate_limited"

    def test_audit_record_redacts_sensitive_fields(self):
        record = mod.audit("totp_validation", "failure",
                           code="123456", secret=SECRET,
                           token="x", secret_id="user-1", reason="replay")
        assert "code" not in record
        assert "secret" not in record
        assert "token" not in record
        assert record["secret_id"] == "user-1"
        assert record["reason"] == "replay"

    def test_error_map_uses_generic_message_for_credential_failures(self):
        generic = mod.error_map("invalid_code")
        assert mod.error_map("replay") == generic
        assert mod.error_map("backup_consumed") == generic
        assert mod.error_map("rate_limited") != generic
        assert mod.error_map("calibration_required") != generic

    def test_weak_secret_rejected(self):
        result = mod.validation(code_at(0), "tooshort", timestamp=T0)
        assert result["ok"] is False
        assert result["reason"] == "weak_secret"

    def test_recovery_returns_audit_and_consumes_code(self):
        digest = mod.hash_backup_code("7777-8888")
        result = mod.recovery({digest}, "7777-8888")
        assert result["recovered"] is True
        assert result["backup_hashes"] == frozenset()
        assert result["audit"]["event"] == "account_recovery"

    def test_totp_code_constant_time_matches_generated_code(self):
        code = mod.generate_totp(SECRET, timestamp=T0)
        assert mod.hmac_compare(code, mod.generate_totp(SECRET, timestamp=T0))
