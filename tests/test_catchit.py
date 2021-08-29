import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "catchit")) # noqa

import catchit

with open("catchit/regexs.json", "r") as regexs:
    REGEXS_DICT = json.loads(regexs.read())


def test_find(tmp_path):
    dir = tmp_path / "sub"
    dir.mkdir()

    key_file = dir / "keyfile.key"
    key_file.touch()
    key_file.write_text("Dummy value")

    rsa_file = dir / ".id_rsa"
    rsa_file.touch()
    rsa_file.write_text("Dummy Value")

    catchit_results = catchit.exec_find(REGEXS_DICT, str(Path(dir).resolve()))
    assert sorted([finding["file_key"] for finding in catchit_results]) == [
        "KEY",
        "RSA_KEYS",
    ]
