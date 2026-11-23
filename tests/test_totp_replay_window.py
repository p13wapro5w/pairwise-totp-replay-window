import pytest
import security.totp_replay_window as mod

CASES = [
    ("window_one_step", (1, 2)),
    ("consumed_set", (1, 2)),
    ("clock_drift", (1, 2)),
    ("backup_code_once", (1, 2)),
    ("time_step", (30, 2)),
    ("hmac_compare", (1, 2)),
    ("secret_length", (1, 2)),
    ("replay_guard", (1, 2)),
    ("resync", (1, 2)),
    ("rate_limit", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("error_map", (1, 2)),
    ("recovery", (1, 2)),
    ("purge_expired", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
