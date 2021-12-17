import argparse
import json
import logging
import math
import ntpath
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from string import ascii_letters, digits
from typing import Any, Dict, List

from config import Catchit_Config
from output import CatchIT_Ouput

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

BASE_PATH = Path(__file__).parent
TS_START = time.time()
FILE_REGEXS = str(BASE_PATH / "regexs.json")
EXEC_GREP_SCRIPT = str(BASE_PATH / "grep_tunnel.sh")
EXEC_FIND_SCRIPT = str(BASE_PATH / "find_tunnel.sh")
INVERSE_GREP = str(BASE_PATH / "inverse_grep.txt")
BASE64_CHARS = "+/=" + ascii_letters + digits

catchit_output = CatchIT_Ouput()
catchit_config = Catchit_Config()


def check_operating_system():
    if platform.system() == "Windows":
        catchit_config.bash = "C:\\Program Files\\Git\\bin\\bash.exe"
        catchit_config.system_path_sep = "**\\*"
        catchit_config.tunnel_flags = "-E"

    elif platform.system() == "Darwin":
        catchit_config.tunnel_flags = "-E"

    elif platform.system() == "Linux":
        catchit_config.tunnel_flags = "-P"


# Parsing the findings from grep subprocess output and returning the refined findings
def getFinding_GREP(
    proc: subprocess.CompletedProcess,
    scanning_path: str,
    confidence: float = 0.4,
    entropy: float = 0,
) -> List[Dict]:
    logger.info("Starting getFinding_grep")

    try:
        findings = []
        proc_output = proc.stdout.decode("utf-8").split("\n")
        for line in proc_output:
            finding = {}
            out_line = line.split(":")
            if len(out_line) < 2:
                break
            if os.name == "nt" and ntpath.isabs(line) and line[1] == 58:
                finding["path"] = out_line[0] + ":" + out_line[1]
                finding["path"] = str(
                    Path(finding["path"]).relative_to(Path(scanning_path))
                )
                finding["line"] = out_line[2]
                finding["match"] = str(":".join(out_line[3:]))
            else:
                finding["path"] = out_line[0]
                finding["path"] = str(
                    Path(finding["path"]).relative_to(Path(scanning_path))
                )
                finding["line"] = out_line[1]
                finding["match"] = str(":".join(out_line[2:]))
            catchit_output.summary["findings"]["code"] += 1
            if (
                confidence >= 0.5
                and shannon_entropy(out_line[2], BASE64_CHARS) > entropy
            ):
                catchit_output.summary["findings"]["blocking_code"] += 1
                finding["type"] = "Blocking"
            else:
                finding["type"] = "Non-Blocking"
            findings.append(finding)

        return findings
    except Exception as e:
        logger.error("Error, skipping this iteration: ", e)
        return []


# Parsing the findings from find subprocess output and returning the refined findings
def getFinding_FIND(
    proc: subprocess.CompletedProcess, scanning_path: str, confidence: float = 0.4
) -> List[Dict]:
    logger.info("Starting getFinding_find")

    try:
        findings = []
        proc_output = proc.stdout.decode("utf-8").split("\n")
        for line in proc_output:
            finding = {}
            out_line = line.split(":")
            if len(out_line[0]) == 0:
                break
            if len(out_line) == 2:
                finding["path"] = out_line[0] + ":" + out_line[1]
                finding["path"] = str(
                    Path(finding["path"]).relative_to(Path(scanning_path))
                )
            else:
                finding["path"] = out_line[0]
                finding["path"] = str(
                    Path(finding["path"]).relative_to(Path(scanning_path))
                )
            catchit_output.summary["findings"]["file"] += 1
            if confidence >= 0.5:
                catchit_output.summary["findings"]["blocking_file"] += 1
                finding["type"] = "Blocking"
            else:
                finding["type"] = "Non-Blocking"

            findings.append(finding)

        return findings
    except Exception as e:
        logger.error("Error, skipping this iteration: ", e)
        return []


# Leverages Code_Scanning regexs from regexs.json to flag suspicious code.
def exec_grep(regexs_json: Dict, scanning_path: str, tunnel_flags: str) -> List[Dict]:
    logger.info("Starting exec grep")

    findings = []
    try:
        for (regex_key, regex_value) in regexs_json["CODE_SCANNING"].items():
            output: Dict[str, Any] = {}
            if "regex" in regex_value.keys():
                regex = regex_value["regex"]
            else:
                logger.error(f"regex missing for {regex_key}")
                continue
            confidence = regex_value.get("confidence", 0)
            entropy = regex_value.get("entropy", 0)
            try:
                if confidence > 0:
                    proc = subprocess.run(
                        [
                            catchit_config.bash,
                            EXEC_GREP_SCRIPT,
                            regex,
                            scanning_path,
                            INVERSE_GREP,
                            tunnel_flags,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=2,
                    )
                    output["findings"] = getFinding_GREP(
                        proc, scanning_path, confidence, entropy
                    )
                    output["regex_key"] = regex_key
                    output["regex_value"] = regex

                    if len(output["findings"]) > 0:
                        findings.append(output)
            except subprocess.TimeoutExpired:
                logger.error("exec_grep times out")

    except Exception as e:
        logger.error("exec_grep encountered an error: ", e)
        return []

    logger.info("exec_grep successfully completed")
    return findings


# Leverages File_Scanning from regexs.json to get suspicious files.
def exec_find(regexs_json: Dict, scanning_path: str, tunnel_flags: str):
    logger.info("Starting exec find")

    findings = []
    try:
        for (file_key, file_value) in regexs_json["FILE_SCANNING"].items():
            output: Dict[str, Any] = {}
            if "regex" in file_value.keys():
                regex = file_value["regex"]
            else:
                logger.error(f"regex missing for {file_key}")
                continue
            confidence = file_value.get("confidence", 0)
            try:
                if confidence > 0:
                    proc = subprocess.run(
                        [
                            catchit_config.bash,
                            EXEC_FIND_SCRIPT,
                            scanning_path,
                            regex,
                            tunnel_flags,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=2,
                    )
                    output["findings"] = getFinding_FIND(
                        proc, scanning_path, confidence
                    )
                    output["file_key"] = file_key
                    output["file_value"] = regex
                    if len(output["findings"]) > 0:
                        findings.append(output)
            except subprocess.TimeoutExpired:
                logger.error("exec_find timed out")
    except Exception as e:
        logger.error("exec_find encountered an error:", e)
        return []

    logger.info("exec_find completed successfully")
    return findings


# Calculate the shannon entropy of the findings from grep and find commands
def shannon_entropy(data: str, iterator: str) -> float:
    try:
        if not data:
            return 0.0
        entropy = 0.0
        for x in iterator:
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy
    except Exception:
        logger.error("error encounterd in calculating shannon entropy")
        return 0.0


def main():
    logger.info("####   STARTING CATCHIT   ####")

    my_parser = argparse.ArgumentParser(description="CatchIt plugins")
    my_parser.add_argument(
        "--bash-path",
        help="Path to the bash supported terminal, defaults to bash",
        default="",
    )
    my_parser.add_argument("--scan-path", help="Path for scan", default="")

    args = vars(my_parser.parse_args())

    catchit_config.scanning_path = str(args["scan_path"]) or os.getcwd()
    catchit_config.bash = str(args["bash_path"]) or catchit_config.bash

    # Get the regexs from regexs.json
    with open(FILE_REGEXS, "r") as f:
        regexs_json = json.load(f)

    # Configure the tunnel flags and bash path based on the operating system
    check_operating_system()

    # Starting grep functions to scan for suspicious code
    time_grep = time.time()
    catchit_output.code = exec_grep(
        regexs_json, catchit_config.scanning_path, catchit_config.tunnel_flags
    )
    catchit_output.summary["execution_time"]["code"] = time.time() - time_grep

    # Starting find functions to scan for suspicious files
    time_find = time.time()
    catchit_output.file = exec_find(
        regexs_json, catchit_config.scanning_path, catchit_config.tunnel_flags
    )
    catchit_output.summary["execution_time"]["file"] = time.time() - time_find

    total_block_findings = (
        catchit_output.summary["findings"]["blocking_code"]
        + catchit_output.summary["findings"]["blocking_file"]
    )

    catchit_output.summary["execution_time"]["total"] = time.time() - TS_START

    print(json.dumps(catchit_output.__dict__, indent=4))

    # Exiting with code 1 for blocked findings
    if total_block_findings != 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
