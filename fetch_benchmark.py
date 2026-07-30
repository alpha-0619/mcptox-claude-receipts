"""Pull the MCPTox benchmark from source. Run this first."""
import subprocess, os, shutil, sys

URL = "https://github.com/zhiqiangwang4/MCPTox-Benchmark.git"
if os.path.exists("response_all.json"):
    print("response_all.json already present, nothing to do")
    sys.exit(0)
subprocess.check_call(["git", "clone", "--depth", "1", URL, "_mcptox"])
for f in ("response_all.json", "pure_tool.json"):
    shutil.copy2(os.path.join("_mcptox", f), f)
print("fetched response_all.json and pure_tool.json")
print("next: python sample.py && python analyze.py")
