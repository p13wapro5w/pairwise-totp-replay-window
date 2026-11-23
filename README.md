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
