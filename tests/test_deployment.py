import importlib.util
import json
from pathlib import Path
import sys
import pytest


def test_owner_bootstrap_is_temporary_private_and_not_overwritten(tmp_path,monkeypatch,capsys):
    path=Path(__file__).resolve().parents[1]/"scripts/prepare_deployment.py"
    spec=importlib.util.spec_from_file_location("prepare_deployment",path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.__file__=str(tmp_path/"scripts/prepare_deployment.py")
    monkeypatch.setattr(sys,"argv",["prepare_deployment.py","--domain","example.test","--owner-login","owner"])
    module.main()
    owner=json.loads((tmp_path/".secrets/owner.json").read_text())
    realm=json.loads((tmp_path/".secrets/realm.json").read_text())
    assert realm["registrationAllowed"] is False
    assert realm["users"][0]["credentials"][0]["temporary"] is True
    assert realm["users"][0]["requiredActions"]==["UPDATE_PASSWORD"]
    assert owner["temporary_password"] not in capsys.readouterr().out
    with pytest.raises(SystemExit): module.main()
