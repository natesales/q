#!/bin/bash

cat README.md | sed '/# Usage/q' > README.tmp.md
printf '\n```text\n' >> README.tmp.md
stty rows 1000 cols 1000
go build && ./q -h | sed -z '$ s/\n$//' >> README.tmp.md
printf '```\n\n### Demo\n' >> README.tmp.md
cat README.md | sed '1,/### Demo/d' >> README.tmp.md
mv README.tmp.md README.md
