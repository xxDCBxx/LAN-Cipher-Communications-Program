import socket
import json
import base64
import hashlib
import hmac
import inspect
import os
import threading
import time
import logging

logger = logging.getLogger(__name__)

UDP_PORT = 50000
TCP_PORT = 50001

_peers: dict = {}
_peers_lock = threading.Lock()
PEER_TIMEOUT = 10

_on_message_cb = None
_on_notification_cb = None

_running = False
_threads: list = []

BAILOUT_ITERATIONS = 200_000
_MAX_ACCEPTED_ITERATIONS = 1_000_000
MAX_PACKET_BYTES = 4 * 1024 * 1024


def make_bailout_record(password: str) -> dict | None:
    if not password:
        return None
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, BAILOUT_ITERATIONS
    )
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
        "iters": BAILOUT_ITERATIONS,
    }


def verify_bailout(candidate: str, record: dict | None) -> bool:
    if not record or not candidate:
        return False
    try:
        salt = base64.b64decode(record["salt"])
        expected = base64.b64decode(record["hash"])
        iters = int(record["iters"])
        if not (1 <= iters <= _MAX_ACCEPTED_ITERATIONS):
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", candidate.encode("utf-8"), salt, iters
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def on_message_received(callback):
    global _on_message_cb
    _on_message_cb = callback


def on_notification_received(callback):
    global _on_notification_cb
    _on_notification_cb = callback


def get_peers() -> dict:
    with _peers_lock:
        now = time.time()
        return {
            ip: info["host"]
            for ip, info in _peers.items()
            if now - info["last_seen"] < PEER_TIMEOUT
        }


def send_message(ip: str, ciphertext_bytes: bytes, decoy_text: str,
                 sender_ip: str, bailout_password: str = "",
                 verifier: dict | None = None) -> None:
    packet = {
        "type": "message",
        "payload": base64.b64encode(ciphertext_bytes).decode("utf-8"),
        "decoy": decoy_text,
        "sender_ip": sender_ip,
    }
    record = make_bailout_record(bailout_password)
    if record is not None:
        packet["bailout"] = record
    if verifier is not None:
        packet["verifier"] = verifier
    _tcp_send(ip, packet)


def send_notification(ip: str, event: str, sender_ip: str) -> None:
    packet = {
        "type": "notification",
        "event": event,
        "sender_ip": sender_ip,
    }
    _tcp_send(ip, packet)


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def start() -> None:
    global _running
    if _running:
        return
    _running = True

    t_beacon = threading.Thread(target=_udp_beacon_loop, daemon=True, name="udp-beacon")
    t_listen = threading.Thread(target=_udp_listen_loop, daemon=True, name="udp-listen")
    t_tcp = threading.Thread(target=_tcp_listen_loop, daemon=True, name="tcp-listen")

    for t in (t_beacon, t_listen, t_tcp):
        t.start()
        _threads.append(t)


def stop() -> None:
    global _running
    _running = False


def _build_beacon() -> bytes:
    return json.dumps({
        "app": "LanCipher",
        "host": socket.gethostname(),
    }).encode("utf-8")


def _udp_beacon_loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        while _running:
            try:
                sock.sendto(_build_beacon(), ("<broadcast>", UDP_PORT))
            except Exception as e:
                logger.debug(f"Beacon send error: {e}")
            time.sleep(3)
    finally:
        sock.close()


def _udp_listen_loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", UDP_PORT))
        sock.settimeout(1.0)
        local_ip = get_local_ip()

        while _running:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                if ip == local_ip or ip == "127.0.0.1":
                    continue
                try:
                    pkt = json.loads(data.decode("utf-8"))
                    if pkt.get("app") == "LanCipher":
                        with _peers_lock:
                            _peers[ip] = {
                                "host": pkt.get("host", ip),
                                "last_seen": time.time(),
                            }
                except Exception:
                    pass
            except socket.timeout:
                pass
            except Exception as e:
                logger.debug(f"UDP listen error: {e}")
    finally:
        sock.close()


def _tcp_listen_loop() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("", TCP_PORT))
        srv.listen(5)
        srv.settimeout(1.0)

        while _running:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=_handle_tcp_connection,
                    args=(conn, addr[0]),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                pass
            except Exception as e:
                logger.debug(f"TCP accept error: {e}")
    finally:
        srv.close()


def _invoke_message_cb(peer_ip, payload_bytes, decoy, sender_ip,
                       bailout_record, verifier):
    args = (peer_ip, payload_bytes, decoy, sender_ip, bailout_record, verifier)
    try:
        params = list(inspect.signature(_on_message_cb).parameters.values())
        if any(p.kind == p.VAR_POSITIONAL for p in params):
            n = len(args)
        else:
            n = sum(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) for p in params)
    except (TypeError, ValueError):
        n = len(args)
    _on_message_cb(*args[:n])


def _handle_tcp_connection(conn: socket.socket, peer_ip: str) -> None:
    try:
        conn.settimeout(10.0)
        chunks = []
        total = 0
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PACKET_BYTES:
                return
            chunks.append(chunk)
        raw = b"".join(chunks)
        pkt = json.loads(raw.decode("utf-8"))
        pkt_type = pkt.get("type")

        if pkt_type == "message" and _on_message_cb:
            payload_bytes = base64.b64decode(pkt["payload"])
            decoy = pkt.get("decoy", "")
            sender_ip = peer_ip
            bailout_record = pkt.get("bailout")
            if not isinstance(bailout_record, dict):
                bailout_record = None
            verifier = pkt.get("verifier")
            if not isinstance(verifier, dict):
                verifier = None
            _invoke_message_cb(peer_ip, payload_bytes, decoy, sender_ip,
                               bailout_record, verifier)

        elif pkt_type == "notification" and _on_notification_cb:
            event = pkt.get("event", "")
            sender_ip = peer_ip
            _on_notification_cb(event, sender_ip)

    except Exception as e:
        logger.debug(f"TCP handler error from {peer_ip}: {e}")
    finally:
        conn.close()


def _tcp_send(ip: str, packet: dict) -> None:
    raw = json.dumps(packet).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(5.0)
        sock.connect((ip, TCP_PORT))
        sock.sendall(raw)
    except ConnectionRefusedError:
        raise ConnectionRefusedError(f"Peer {ip} refused the connection (port {TCP_PORT}).")
    except socket.timeout:
        raise TimeoutError(f"Connection to {ip} timed out.")
    except Exception as e:
        raise RuntimeError(f"Failed to send to {ip}: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    import sys

    print("network.py — LAN discovery demo")
    print(f"Local IP : {get_local_ip()}")
    print(f"Hostname : {socket.gethostname()}")
    print()

    def _msg_cb(ip, ct_bytes, decoy, sender_ip, bailout_record):
        print(f"[MESSAGE] from {ip} | decoy='{decoy}' | ciphertext bytes={len(ct_bytes)} "
              f"| bailout={'yes' if bailout_record else 'no'}")

    def _notif_cb(event, sender_ip):
        print(f"[NOTIFICATION] event='{event}' from {sender_ip}")

    on_message_received(_msg_cb)
    on_notification_received(_notif_cb)

    start()
    print("Network started. Listening for peers...")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            peers = get_peers()
            if peers:
                print(f"  Active peers: {peers}")
            else:
                print("  No peers found yet.")
            time.sleep(3)
    except KeyboardInterrupt:
        stop()
        print("\nStopped.")
        sys.exit(0)
