import shlex
from core.executor import run_command


def run(target, verbose=False):
    sslscan_out, _ = run_command(f"sslscan {shlex.quote(target)}", verbose)
    testssl_out, _ = run_command(f"testssl.sh --quiet --fast {shlex.quote(target)}", verbose, timeout=300)
    weak = any(x in (sslscan_out + testssl_out).lower() for x in ["tlsv1", "tls 1.0", "rc4", "3des", "expired"])
    return {"raw": {"sslscan": sslscan_out, "testssl": testssl_out}, "parsed": {"weak_tls_or_cert": weak, "medium_risk_count": 1 if weak else 0}}
