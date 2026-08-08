from core.health import assert_healthy, check


def test_health_ok():
    result = check()
    assert result["service"] == "ventura-seg"
    assert result["status"] == "ok"
    assert result["missing_policies"] == []
    assert_healthy()
