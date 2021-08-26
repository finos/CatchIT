from typing import Any, Dict, List


class CatchIT_Ouput:
    def __init__(self):
        self.code: List[Dict] = []
        self.file: List[Dict] = []
        self.summary: Dict[str, Any] = {
            "findings": {
                "code": 0,
                "file": 0,
                "blocking_code": 0,
                "blocking_file": 0,
            },
            "execution_time": {
                "code": 0.0,
                "file": 0.0,
            },
        }
