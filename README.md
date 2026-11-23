# pairwise-totp-replay-window

## 领域

安全

## 主题

TOTP 重放窗口

## 说明

单步窗口、已消费集合与时钟漂移。

初始状态下 `security/totp_replay_window.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。

## 实现要点

针对安全评审的四项问题，`security/totp_replay_window.py` 的修复策略：

1. **窗口收窄到 ±1 步**：`WINDOW_STEPS = 1`（RFC 6238 推荐值），`window_one_step()`
   作为结构性兜底，校验循环只扫描 `-1/0/+1` 三个计数器；旧的 ±10 步
   （`LEGACY_WINDOW_STEPS`）仅保留为“只检测、不接受”的漂移探测范围。
2. **已消费集合防重放**：验证成功即把 `(密钥标识, 计数器)` 写入带过期时间的
   已消费集合（`consumed_set` / `replay_guard`），同码重复提交返回 `replay`；
   过期条目由 `purge_expired()` 清理，集合不会无限增长。
3. **时钟漂移检测与校准提示**：`clock_drift()` 量化漂移步数；±1 步内由
   `resync()` 有限补偿，连续同向漂移才采纳补偿偏移并产生 `clock_resync`
   审计事件；越窗码即使本身是合法 TOTP 也拒绝，返回 `calibration_required`
   并提示校准时间，绝不静默放行。
4. **备份码一次性作废**：备份码仅以 SHA-256 哈希存储（`hash_backup_code`），
   `backup_code_once()` 常量时间匹配，命中即从集合中剔除，二次使用返回
   `backup_consumed`。

配套机制：HOTP/TOTP 生成（通过 RFC 6238 附录 B 测试向量）、常量时间比较
（`hmac_compare`）、密钥 ≥160 bit 强度校验（`secret_length`）、滑动窗口失败
限流（`RateLimiter` / `rate_limit`）、敏感因子脱敏的审计日志（`AuditLog` /
`audit`）、统一对外错误文案（`error_map`，凭证类失败不区分具体因子）。

模块级函数为无状态纯函数，`TOTPValidator` 是线程安全的有状态入口，二者共用
同一套安全机制。测试见 `tests/test_security_properties.py`。
