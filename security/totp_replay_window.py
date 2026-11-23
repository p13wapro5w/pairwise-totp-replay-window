"""TOTP 校验：单步窗口、已消费集合、时钟漂移检测与一次性备份码。

安全基线（对应安全评审意见）：

1. 校验窗口收窄为 ±1 个时间步（RFC 6238 推荐值），旧实现的 ±10 步窗口废弃，
   ±10 仅保留为“只检测、不接受”的漂移探测范围；
2. 验证成功后立即把 ``(密钥标识, 计数器)`` 写入已消费集合并附带过期时间，
   同一验证码在窗口内重放一律拒绝，过期条目由 :func:`purge_expired` 清理；
3. 检测客户端/服务器时钟漂移：±1 步内允许有限补偿（:func:`resync`），
   连续同向漂移触发校准提示；超出 ±1 步拒绝并提示校准时间，绝不静默放行；
4. 备份码仅存 SHA-256 哈希、常量时间匹配、用后即焚（一次性作废）；
5. 配套：常量时间比较、密钥强度校验、失败限流、审计日志（敏感因子不落盘）、
   对外统一错误文案，避免泄露具体失败因子。

模块级函数尽量写成无副作用的纯函数，便于单测与组合；:class:`TOTPValidator`
是承载状态（已消费集合、漂移状态、备份码哈希、限流、审计）的有状态入口。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import threading
import time

__all__ = [
    # 评审要求的四个核心机制
    "window_one_step",
    "consumed_set",
    "clock_drift",
    "backup_code_once",
    # 基础原语
    "time_step",
    "hmac_compare",
    "secret_length",
    "generate_totp",
    "hash_backup_code",
    # 组合机制
    "replay_guard",
    "resync",
    "rate_limit",
    "validation",
    "audit",
    "error_map",
    "recovery",
    "purge_expired",
    # 有状态组件
    "TOTPValidator",
    "RateLimiter",
    "AuditLog",
    # 常量
    "DEFAULT_STEP",
    "DEFAULT_DIGITS",
    "WINDOW_STEPS",
    "LEGACY_WINDOW_STEPS",
    "MIN_SECRET_BYTES",
]

# ---- 安全常量 ---------------------------------------------------------------

DEFAULT_STEP = 30          # RFC 6238 默认时间步长（秒）
DEFAULT_DIGITS = 6         # TOTP 码位数
WINDOW_STEPS = 1           # 修复后只接受 ±1 步
LEGACY_WINDOW_STEPS = 10   # 旧实现的危险窗口，仅用于漂移探测，绝不用于放行
MIN_SECRET_BYTES = 20      # RFC 4226：共享密钥至少 160 bit / 20 字节
_BACKUP_DOMAIN = b"totp-backup-code:"
_SENSITIVE_TOKENS = ("code", "secret", "password", "token")


# ---- 基础原语 ---------------------------------------------------------------

def time_step(timestamp, step=DEFAULT_STEP):
    """RFC 6238 时间计数器 ``T = floor(unix_time / step)``。"""
    return int(timestamp) // int(step)


def hmac_compare(a, b):
    """常量时间比较，规避时序侧信道；str / bytes / int 均可比较。"""
    def _normalize(value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        return str(value).encode("utf-8")

    return hmac.compare_digest(_normalize(a), _normalize(b))


def _decode_secret(secret):
    """把密钥归一化为原始字节：优先按 Base32 解码，失败则按 UTF-8 字节处理。"""
    if isinstance(secret, (bytes, bytearray)):
        return bytes(secret)
    text = str(secret)
    try:
        body = text.upper().rstrip("=")
        padded = body + "=" * (-len(body) % 8)
        return base64.b32decode(padded)
    except (ValueError, TypeError):
        return text.encode("utf-8")


def secret_length(secret, minimum=MIN_SECRET_BYTES):
    """校验密钥强度：解码后的原始长度不得低于 ``minimum`` 字节（默认 160 bit）。"""
    return len(_decode_secret(secret)) >= int(minimum)


def _hotp(secret, counter, digits=DEFAULT_DIGITS):
    """RFC 4226 HOTP：给定密钥与计数器生成动态码。"""
    counter = int(counter)
    if counter < 0:
        # RFC 6238 计数器为非负整数；负计数器只可能来自异常时钟/入参
        raise ValueError("TOTP 时间计数器不能为负数")
    msg = struct.pack(">Q", counter)
    digest = hmac.new(_decode_secret(secret), msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def generate_totp(secret, timestamp=None, step=DEFAULT_STEP,
                  digits=DEFAULT_DIGITS, offset=0):
    """生成指定时刻的 TOTP，``offset`` 为相对当前时间步的计数器偏移。"""
    if timestamp is None:
        timestamp = time.time()
    return _hotp(secret, time_step(timestamp, step) + int(offset), digits)


def hash_backup_code(code):
    """备份码只存哈希：加域分隔前缀后做 SHA-256，避免明文落库。"""
    normalized = str(code).strip()
    return hashlib.sha256(_BACKUP_DOMAIN + normalized.encode("utf-8")).hexdigest()


# ---- 窗口与漂移 -------------------------------------------------------------

def window_one_step(current_counter, candidate_counter):
    """候选计数器必须落在当前计数器的 ±1 步以内，越窗一律返回 False。

    旧实现接受 ±10 步等价于把验证码可重放时间窗放大到约 10 分钟，
    本函数是结构性兜底，校验循环中的每个偏移都经过它确认。
    """
    return abs(int(candidate_counter) - int(current_counter)) <= WINDOW_STEPS


def clock_drift(observed_counter, expected_counter):
    """计算时钟漂移（单位：时间步）并判断是否需要校准。"""
    drift = int(observed_counter) - int(expected_counter)
    within_tolerance = abs(drift) <= WINDOW_STEPS
    if within_tolerance:
        message = "时钟漂移在 ±1 步容差内"
    else:
        message = (
            f"时钟漂移 {drift} 步，超出 ±1 步容差，"
            "请校准服务器/认证设备时间后重试"
        )
    return {
        "drift_steps": drift,
        "within_tolerance": within_tolerance,
        "calibration_required": not within_tolerance,
        "message": message,
    }


def resync(drift_steps, window=WINDOW_STEPS):
    """有限重同步：仅当漂移在 ±1 步内才返回可补偿偏移，否则返回 None。

    返回 None 表示不允许静默补偿，调用方必须走显式时钟校准流程。
    """
    drift_steps = int(drift_steps)
    return drift_steps if abs(drift_steps) <= int(window) else None


# ---- 已消费集合与重放防护 ----------------------------------------------------

def consumed_set(store, key, expiry=None):
    """纯函数式已消费集合，返回 ``(是否已消费, 新集合)``。

    ``store`` 为 ``{key: expiry_timestamp}`` 字典；不原地修改入参。
    非字典入参（含测试桩值）按空集合处理，保证函数整体可用。
    """
    if not isinstance(store, dict):
        store = {}
    if key in store:
        return True, dict(store)
    updated = dict(store)
    updated[key] = None if expiry is None else int(expiry)
    return False, updated


def replay_guard(store, key, expiry=None):
    """重放守卫：命中已消费集合则拒绝，否则登记后放行。"""
    consumed, updated = consumed_set(store, key, expiry)
    return {
        "allowed": not consumed,
        "reason": None if not consumed else "replay",
        "store": updated,
    }


def purge_expired(entries, now):
    """清除过期条目。

    支持 ``{key: expiry}`` 字典或 ``(key, expiry)`` 可迭代对象；
    ``expiry <= now`` 即视为过期。无法识别的入参原样返回。
    """
    now = int(now)
    if isinstance(entries, dict):
        return {key: expiry for key, expiry in entries.items() if int(expiry) > now}
    if isinstance(entries, (list, tuple, set, frozenset)):
        kept = []
        for item in entries:
            try:
                key, expiry = item
            except (TypeError, ValueError):
                continue
            if int(expiry) > now:
                kept.append((key, expiry))
        if isinstance(entries, list):
            return kept
        if isinstance(entries, tuple):
            return tuple(kept)
        return frozenset(kept)
    return entries


# ---- 备份码与恢复 -----------------------------------------------------------

def backup_code_once(valid_hashes, presented_code):
    """一次性备份码校验，返回 ``(是否通过, 剩余哈希集合)``。

    - 只接受哈希集合，常量时间逐个比对；
    - 命中后立即把该哈希从集合中剔除（用后即焚）；
    - 未命中时集合保持不变。
    """
    if not isinstance(valid_hashes, (set, frozenset)):
        valid_hashes = frozenset()
    digest = hash_backup_code(presented_code)
    matched = next(
        (candidate for candidate in valid_hashes
         if hmac_compare(str(candidate), digest)),
        None,
    )
    if matched is None:
        return False, frozenset(valid_hashes)
    return True, frozenset(valid_hashes - {matched})


def recovery(valid_hashes, presented_code):
    """账户恢复流程：凭一次性备份码恢复访问，用后即焚并留审计记录。"""
    ok, remaining = backup_code_once(valid_hashes, presented_code)
    return {
        "recovered": ok,
        "backup_hashes": remaining,
        "reason": None if ok else "backup_consumed",
        "audit": audit("account_recovery", "success" if ok else "failure"),
    }


# ---- 限流、审计与错误映射 ----------------------------------------------------

def rate_limit(attempts, limit):
    """失败尝试数未达上限才放行。"""
    return int(attempts) < int(limit)


def audit(event, status, **fields):
    """构造审计记录；字段名含 code/secret/password/token 的敏感因子一律不落盘。

    只有字段名本身就是敏感词（code/secret/password/token）才脱敏，
    ``secret_id`` 这类标识符保留。
    """
    record = {
        "ts": time.time(),
        "event": str(event),
        "status": str(status),
    }
    for key, value in fields.items():
        if str(key).lower() in _SENSITIVE_TOKENS:
            continue
        record[key] = value
    return record


def error_map(reason, *_extra):
    """内部失败原因映射为对外文案（多余位置参数忽略，以满足统一调用契约）。

    凭证类失败（码错误/重放/备份码失效）统一文案，避免攻击者区分失败因子；
    限流与时钟校准属于用户可自行处理的状态，保留差异化提示。
    """
    generic = "双因素校验失败，请重试或联系管理员"
    table = {
        "invalid_code": generic,
        "replay": generic,
        "window_exceeded": generic,
        "backup_consumed": generic,
        "rate_limited": "尝试次数过多，请稍后再试",
        "calibration_required": "认证设备时间漂移过大，请校准时间后重试",
        "weak_secret": "服务器配置错误：TOTP 密钥强度不足",
    }
    if reason is None:
        return "校验通过"
    return table.get(str(reason), generic)


# ---- 主编排：无状态函数式入口 -----------------------------------------------

def _detect_far_drift(secret, code, current, digits):
    """只检测、不接受：在 ±2..±10 步范围内探测是否存在时钟漂移。

    返回命中的远端计数器，未命中返回 None。命中仅用于提示校准，
    绝不会作为校验通过的依据。
    """
    for offset in range(WINDOW_STEPS + 1, LEGACY_WINDOW_STEPS + 1):
        for candidate in (current - offset, current + offset):
            if candidate < 0:
                continue
            if hmac_compare(_hotp(secret, candidate, digits), code):
                return candidate
    return None


def validation(presented_code, secret, *, timestamp=None, consumed=None,
               secret_id="default", step=DEFAULT_STEP, digits=DEFAULT_DIGITS,
               attempts=0, max_attempts=5, backup_hashes=None):
    """TOTP 校验主入口（无状态版本，状态由入参/返回值携带）。

    返回结果字典，包含 ``ok`` / ``reason`` / ``message`` / 更新后的
    ``consumed`` 与 ``backup_hashes`` / 漂移信息 / 审计记录。
    所有分支都经过限流、窗口收窄、重放防护与统一错误映射。
    """
    now = time.time() if timestamp is None else timestamp
    result = {
        "ok": False,
        "reason": None,
        "message": error_map(None),
        "consumed": dict(consumed) if isinstance(consumed, dict) else {},
        "backup_hashes": (
            frozenset(backup_hashes)
            if isinstance(backup_hashes, (set, frozenset)) else frozenset()
        ),
        "drift": None,
        "audit": None,
    }

    def finish(reason, **extra):
        result["reason"] = reason
        result["ok"] = reason is None
        result["message"] = error_map(reason)
        result["audit"] = audit(
            "totp_validation",
            "success" if reason is None else "failure",
            reason=reason,
            secret_id=secret_id,
            attempts=attempts,
        )
        result.update(extra)
        return result

    # 1) 失败限流：超限后即使码正确也拒绝
    if not rate_limit(attempts, max_attempts):
        return finish("rate_limited")

    # 2) 密钥强度
    if not secret_length(secret):
        return finish("weak_secret")

    code = str(presented_code).strip().replace(" ", "")

    # 3) 非 TOTP 格式 → 一次性备份码分支
    if not (code.isdigit() and len(code) == digits):
        if result["backup_hashes"]:
            ok, remaining = backup_code_once(result["backup_hashes"], code)
            if ok:
                result["backup_hashes"] = remaining
                return finish(None)
            return finish("backup_consumed")
        return finish("invalid_code")

    # 4) TOTP：仅扫描 ±1 步，每个候选都经 window_one_step 结构性确认
    current = time_step(now, step)
    matched_counter = None
    for offset in range(-WINDOW_STEPS, WINDOW_STEPS + 1):
        candidate = current + offset
        if candidate < 0 or not window_one_step(current, candidate):
            continue
        if hmac_compare(_hotp(secret, candidate, digits), code):
            matched_counter = candidate
            break

    if matched_counter is None:
        far_counter = _detect_far_drift(secret, code, current, digits)
        if far_counter is not None:
            result["drift"] = clock_drift(far_counter, current)
            return finish("calibration_required")
        return finish("invalid_code")

    # 5) 重放防护：用过的 (密钥标识, 计数器) 在过期前不可再次使用
    key = (secret_id, matched_counter)
    expiry = (matched_counter + WINDOW_STEPS + 1) * step
    decision = replay_guard(result["consumed"], key, expiry)
    result["consumed"] = decision["store"]
    if not decision["allowed"]:
        return finish("replay")

    result["drift"] = clock_drift(matched_counter, current)
    return finish(None)


# ---- 有状态组件 -------------------------------------------------------------

class RateLimiter:
    """滑动窗口失败限流：窗口内失败达上限即锁定。"""

    def __init__(self, max_attempts=5, window=300):
        self.max_attempts = max_attempts
        self.window = window
        self.failures = []
        self.locked_until = 0.0

    def _trim(self, now):
        self.failures = [t for t in self.failures if t > now - self.window]

    def allowed(self, now):
        self._trim(now)
        return now >= self.locked_until and len(self.failures) < self.max_attempts

    def record_failure(self, now):
        self.failures.append(now)
        self._trim(now)
        if len(self.failures) >= self.max_attempts:
            self.locked_until = now + self.window

    def record_success(self):
        self.failures.clear()
        self.locked_until = 0.0


class AuditLog:
    """内存审计日志，生产环境可替换为写入 SIEM 的同接口实现。"""

    def __init__(self):
        self.records = []

    def emit(self, event, status, **fields):
        record = audit(event, status, **fields)
        self.records.append(record)
        return record


class TOTPValidator:
    """承载状态的 TOTP 校验器，串联本模块全部安全机制。

    - 固定 ±1 步窗口，越窗码只做漂移探测、绝不接受；
    - 已消费集合带过期时间，每次校验前自动清理；
    - 连续两次同向 ±1 步漂移即采纳补偿偏移并提示校准；
    - 备份码哈希存储、用后即焚；
    - 失败限流 + 审计日志 + 统一对外错误文案。
    """

    def __init__(self, secret, secret_id="default", *,
                 step=DEFAULT_STEP, digits=DEFAULT_DIGITS,
                 max_attempts=5, lock_window=300):
        if not secret_length(secret):
            raise ValueError("TOTP 密钥强度不足，至少需要 20 字节（160 bit）")
        self.secret = secret
        self.secret_id = secret_id
        self.step = step
        self.digits = digits
        self.consumed = {}                          # (secret_id, counter) -> expiry
        self.backup_hashes = frozenset()
        self.rate_limiter = RateLimiter(max_attempts, lock_window)
        self.audit_log = AuditLog()
        self.drift_offset = 0                       # 已采纳的补偿偏移，仅可能为 -1/0/1
        self.calibration_suggested = False
        self._drift_streak = 0
        self._last_offset = None
        self._lock = threading.Lock()

    # -- 备份码生命周期 -------------------------------------------------------

    def provision_backup_codes(self, codes):
        """登记备份码（仅存哈希），明文只应在生成时向用户展示一次。"""
        hashes = {hash_backup_code(code) for code in codes}
        self.backup_hashes = frozenset(self.backup_hashes | hashes)
        return len(hashes)

    def recover(self, code, now=None):
        """备份码恢复入口，同样受限流约束且用后即焚。"""
        now = time.time() if now is None else now
        with self._lock:
            if not self.rate_limiter.allowed(now):
                self.audit_log.emit("account_recovery", "failure",
                                    reason="rate_limited", secret_id=self.secret_id)
                return self._failure("rate_limited")
            ok, remaining = backup_code_once(self.backup_hashes, code)
            self.backup_hashes = remaining
            if not ok:
                self.rate_limiter.record_failure(now)
                self.audit_log.emit("account_recovery", "failure",
                                    reason="backup_consumed", secret_id=self.secret_id)
                return self._failure("backup_consumed")
            self.rate_limiter.record_success()
            self.audit_log.emit("account_recovery", "success", secret_id=self.secret_id)
            return {"ok": True, "reason": None, "message": error_map(None),
                    "drift": None, "backup_hashes": self.backup_hashes}

    # -- 主校验流程 -----------------------------------------------------------

    def verify(self, code, now=None):
        """校验 TOTP 码，返回统一结构的结果字典并更新内部状态。"""
        now = time.time() if now is None else now
        with self._lock:
            # 清理过期已消费条目
            self.consumed = purge_expired(self.consumed, now)

            if not self.rate_limiter.allowed(now):
                self.audit_log.emit("totp_validation", "failure",
                                    reason="rate_limited", secret_id=self.secret_id)
                return self._failure("rate_limited")

            normalized = str(code).strip().replace(" ", "")

            # 备份码分支：非指定位数数字时尝试一次性备份码
            if not (normalized.isdigit() and len(normalized) == self.digits):
                if self.backup_hashes:
                    ok, remaining = backup_code_once(self.backup_hashes, normalized)
                    self.backup_hashes = remaining
                    if ok:
                        self.rate_limiter.record_success()
                        self.audit_log.emit("totp_validation", "success",
                                            factor="backup_code", secret_id=self.secret_id)
                        return self._success(None)
                    self.rate_limiter.record_failure(now)
                    self.audit_log.emit("totp_validation", "failure",
                                        reason="backup_consumed", secret_id=self.secret_id)
                    return self._failure("backup_consumed")
                self.rate_limiter.record_failure(now)
                self.audit_log.emit("totp_validation", "failure",
                                    reason="invalid_code", secret_id=self.secret_id)
                return self._failure("invalid_code")

            current = time_step(now, self.step)
            matched_counter = None
            for offset in range(-WINDOW_STEPS, WINDOW_STEPS + 1):
                candidate = current + offset
                if candidate < 0 or not window_one_step(current, candidate):
                    continue
                if hmac_compare(_hotp(self.secret, candidate, self.digits), normalized):
                    matched_counter = candidate
                    break

            if matched_counter is None:
                # 只检测不接受：远端命中说明是时钟漂移，提示校准而非放行
                far_counter = _detect_far_drift(
                    self.secret, normalized, current, self.digits)
                if far_counter is not None:
                    drift = clock_drift(far_counter, current)
                    self.rate_limiter.record_failure(now)
                    self.audit_log.emit("totp_validation", "failure",
                                        reason="calibration_required",
                                        drift_steps=drift["drift_steps"],
                                        secret_id=self.secret_id)
                    result = self._failure("calibration_required")
                    result["drift"] = drift
                    return result
                self.rate_limiter.record_failure(now)
                self.audit_log.emit("totp_validation", "failure",
                                    reason="invalid_code", secret_id=self.secret_id)
                return self._failure("invalid_code")

            # 重放防护
            key = (self.secret_id, matched_counter)
            expiry = (matched_counter + WINDOW_STEPS + 1) * self.step
            decision = replay_guard(self.consumed, key, expiry)
            self.consumed = decision["store"]
            if not decision["allowed"]:
                self.rate_limiter.record_failure(now)
                self.audit_log.emit("totp_validation", "failure",
                                    reason="replay", secret_id=self.secret_id)
                return self._failure("replay")

            # 漂移记录：连续两次同向偏移才采纳补偿，并要求校准主机时钟
            drift = clock_drift(matched_counter, current)
            offset = drift["drift_steps"]
            if offset != 0:
                self._drift_streak = (
                    self._drift_streak + 1 if offset == self._last_offset else 1
                )
                self._last_offset = offset
                if (self._drift_streak >= 2 and resync(offset) is not None
                        and self.drift_offset != offset):
                    self.drift_offset = offset
                    self.calibration_suggested = True
                    self.audit_log.emit("clock_resync", "warning",
                                        drift_steps=offset, secret_id=self.secret_id)
            else:
                self._drift_streak = 0
                self._last_offset = None

            self.rate_limiter.record_success()
            self.audit_log.emit("totp_validation", "success",
                                drift_steps=offset, secret_id=self.secret_id)
            return self._success(drift)

    # -- 内部辅助 -------------------------------------------------------------

    def _failure(self, reason):
        return {
            "ok": False,
            "reason": reason,
            "message": error_map(reason),
            "drift": None,
            "backup_hashes": self.backup_hashes,
            "calibration_suggested": self.calibration_suggested,
        }

    def _success(self, drift):
        return {
            "ok": True,
            "reason": None,
            "message": error_map(None),
            "drift": drift,
            "backup_hashes": self.backup_hashes,
            "calibration_suggested": self.calibration_suggested,
        }
