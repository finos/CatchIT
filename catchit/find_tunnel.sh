#!/bin/bash
timeout 1s find $1 -not -path "*/venv/*" -not -empty 2>/dev/null | grep -P $2
