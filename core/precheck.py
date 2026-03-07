import shutil
from core.config import REQUIRED_TOOLS


def run_precheck(auto_install=False):
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        print(f"[!] Strict precheck failed. Missing tools: {missing}")
        if auto_install:
            print("[!] Auto-install is intentionally disabled in this strict build.")
        return False
    print("[+] Strict precheck passed.")
    return True
