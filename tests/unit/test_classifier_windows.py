from mcp_customs.detectors.classifier import MAX_TOKENS, STRIDE, OnnxClassifier, budget

CLS, SEP = 1, 2


def ids(body_length: int) -> list[int]:
    return [CLS, *range(100, 100 + body_length), SEP]


def test_short_text_is_one_window() -> None:
    assert OnnxClassifier()._windows(ids(10)) == [ids(10)]


def test_long_text_windows_overlap_and_cover_everything() -> None:
    body_length = 2000
    windows = OnnxClassifier()._windows(ids(body_length))
    assert len(windows) > 1
    assert all(len(w) <= MAX_TOKENS and w[0] == CLS and w[-1] == SEP for w in windows)
    covered = {token for window in windows for token in window[1:-1]}
    assert covered == set(range(100, 100 + body_length))
    first, second = windows[0][1:-1], windows[1][1:-1]
    assert len(set(first) & set(second)) == STRIDE


def test_text_just_over_the_limit_needs_two_windows() -> None:
    windows = OnnxClassifier()._windows(ids(MAX_TOKENS))
    assert len(windows) == 2


def test_the_character_budget_keeps_both_ends() -> None:
    text = "HEAD" + "x" * 10_000 + "TAIL"
    kept = budget(text, 1000)
    assert len(kept) == 1001
    assert kept.startswith("HEAD")
    assert kept.endswith("TAIL")
    assert budget("short", 1000) == "short"
    assert budget(text, None) == text
