from evidence_to_attack.normalize import normalize


def test_collapses_whitespace_and_trims() -> None:
    assert normalize("  powershell.exe\t -enc\n\n  AAAA  ") == "powershell.exe -enc AAAA"

def test_removes_zero_width_characters() -> None:
    assert normalize("mimi\u200bkatz") == "mimikatz"
    assert normalize("\ufeffheader") == "header"
    
def test_folds_full_width_letters() -> None:
    assert normalize("cmd.exe") == "cmd.exe"
    
def test_keeps_case() -> None:
    assert normalize("LSASS") == "LSASS"