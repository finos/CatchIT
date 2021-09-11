import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "catchit"))  # noqa

import catchit  # type: ignore # noqa

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

    catchit_results = catchit.exec_find(REGEXS_DICT, str(dir))
    assert sorted([finding["file_key"] for finding in catchit_results]) == [
        "KEY",
        "RSA_KEYS",
    ]

    sub_dir = dir / "sub_dir"
    assert catchit.exec_find(REGEXS_DICT, str(sub_dir)) == []


def test_grep(tmp_path):
    dir = tmp_path / "sub"
    dir.mkdir()

    txt_file = dir / "sample.txt"
    txt_file.touch()
    txt_file.write_text(
        """
password = "fsdfdsfdsfdfgdfg1234"

-u anirudd -p asfddsfdfdfgfdg

this_is_not_a_key = AKIAAIOSFODNN7EXAMPLE

    """
    )

    catchit_results = catchit.exec_grep(REGEXS_DICT, dir)
    assert sorted([finding["regex_key"] for finding in catchit_results]) == [
        "AWS-ID",
        "PASSWORD",
        "PASSWORD-ARGUMENT",
    ]
