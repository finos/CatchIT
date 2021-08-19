#!/bin/bash
timeout 1s grep -nroI -P --exclude-dir=.git --exclude-dir=.svn --exclude-dir=node_modules --exclude-dir=venv --exclude='regexs.json' "$1" $2 | grep -iE -v -f $3
# --color=always
