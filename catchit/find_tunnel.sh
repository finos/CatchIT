#!/bin/bash
find $1 -not -path "*/venv/*" -not -empty 2>/dev/null | grep $3 $2
