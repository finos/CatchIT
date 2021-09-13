import json
import platform
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).parent.parent / "catchit"))  # noqa

import catchit  # type: ignore # noqa

with open("catchit/regexs.json", "r") as regexs:
    REGEXS_DICT = json.loads(regexs.read())


@pytest.fixture
def tunnel_flags():
    if platform.system() == "Darwin":
        return "-E"
    elif platform.system() == "Linux":
        return "-P"


def test_find(tmp_path, tunnel_flags):
    dir = tmp_path / "sub"
    dir.mkdir()

    key_file = dir / "keyfile.key"
    key_file.touch()
    key_file.write_text("Dummy value")

    rsa_file = dir / ".id_rsa"
    rsa_file.touch()
    rsa_file.write_text("Dummy Value")

    catchit_results = catchit.exec_find(REGEXS_DICT, dir, tunnel_flags)
    assert sorted([finding["file_key"] for finding in catchit_results]) == [
        "KEY",
        "RSA_KEYS",
    ]

    sub_dir = dir / "sub_dir"
    assert catchit.exec_find(REGEXS_DICT, sub_dir, tunnel_flags) == []


def test_grep(tmp_path, tunnel_flags):
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

    catchit_results = catchit.exec_grep(REGEXS_DICT, dir, tunnel_flags)
    assert sorted([finding["regex_key"] for finding in catchit_results]) == [
        "AWS-ID",
        "PASSWORD",
        "PASSWORD-ARGUMENT",
    ]
