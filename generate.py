#!/usr/bin/env python3
# README.md generator

import os

delimiter = "[comment]: <> (usage)"
readme = open("README.md", "r")
parts = readme.read().split(delimiter+"\n")
readme.close()
with open("README.md", "w") as readme:
    readme.write(f"""{parts[0].strip()}
{delimiter}
```
{os.popen("go build && ./q -h").read().strip()}
```
{delimiter}
{parts[2]}""")
