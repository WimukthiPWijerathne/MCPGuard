# attack_tests/test_phase2_suite.py
from security.models import UserContext, Role
from security.risk import RiskEngine
from security.rate_limit import RateLimiter

def test_risk_scoring():
    print("\n=== TESTING RISK ENGINE ===")
    
    # Low Risk
    res1 = RiskEngine.calculate(
        tool="read_file",
        role=Role.VIEWER,
        path="readme.txt",
        resource_classification="PUBLIC"
    )
    print(f"[TEST 1] Public Read Score: {res1.score} | Decision: {res1.decision} | Level: {res1.level}")
    assert res1.decision == "ALLOW"

    # Critical Risk (Path traversal + Secret)
    res2 = RiskEngine.calculate(
        tool="read_file",
        role=Role.DEVELOPER,
        path="../secrets/credentials.txt",
        resource_classification="SECRET"
    )
    print(f"[TEST 2] Secret Access Score: {res2.score} | Decision: {res2.decision} | Level: {res2.level}")
    assert res2.decision == "BLOCK"

def test_rate_limiting():
    print("\n=== TESTING RATE LIMITER ===")
    limiter = RateLimiter(max_requests=3, window_seconds=5)
    
    for i in range(4):
        allowed, msg = limiter.check(user_id="user_01", tool_name="list_files")
        print(f"Call {i+1}: Allowed={allowed} | {msg}")
        if i == 3:
            assert not allowed

if __name__ == "__main__":
    test_risk_scoring()
    test_rate_limiting()
    print("\n[ALL PHASE 2 ENGINE TESTS PASSED]")