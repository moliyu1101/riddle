# -*- coding: utf-8 -*-
import sys
data = sys.stdin.buffer.read()
text = data.decode("utf-8", "replace")
text = text.replace("基于 AutoHunter（StanleyNull）二次开发的", "")
sys.stdout.buffer.write(text.encode("utf-8"))
