import socket


def run(target, verbose=False):
    banners = {}
    for port in [21, 22, 23, 25, 80, 110, 143, 443, 445, 587, 8080, 9100]:
        try:
            s = socket.create_connection((target, port), timeout=2)
            try:
                s.sendall(b"\r\n")
            except Exception:
                pass
            data = s.recv(256)
            banners[str(port)] = data.decode(errors="ignore").strip()
            s.close()
        except Exception:
            continue
    return {"raw": {"banners": banners}, "parsed": {"banner_count": len(banners)}}
