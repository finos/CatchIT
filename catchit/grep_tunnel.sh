#!/bin/bash
grep -nroI -E --exclude-dir=.git --exclude-dir=.svn --exclude-dir=node_modules --exclude-dir=venv --exclude='regexs.json' "$1" $2 | grep -iE -v -f $3
