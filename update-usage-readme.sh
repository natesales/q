#!/bin/bash

cat README.md | sed '/# Usage/q' > README.tmp.md
echo '```' >> README.tmp.md
go build && ./q -h | sed -z '$ s/\n$//' >> README.tmp.md
printf '```\n\n### Demo\n' >> README.tmp.md
cat README.md | sed '1,/### Demo/d' >> README.tmp.md
mv README.tmp.md README.md
