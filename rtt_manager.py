#!/usr/bin/env python3
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from queue import Empty, Queue

RUN_AS_USER = os.environ.get("RUN_AS_USER", "aruw")
JLINK_DIR = os.environ.get("JLINK_DIR", f"/home/{RUN_AS_USER}/JLink_Linux_V812g_arm")

DEVICE = os.environ.get("JLINK_DEVICE", "STM32F427II")
IFACE = os.environ.get("JLINK_IFACE", "SWD")
SPEED_KHZ = int(os.environ.get("JLINK_SPEED_KHZ", "4000"))

RS_HOST = os.environ.get("JLINK_RS_HOST", "127.0.0.1")
RS_PORT = int(os.environ.get("JLINK_RS_PORT", "19020"))
RTT_PORT = int(os.environ.get("JLINK_RTT_PORT", "19051"))

RTT_STREAM_ENABLED = os.environ.get("JLINK_RTT_STREAM_ENABLED", "1") == "1"
RTT_STREAM_PORT = int(os.environ.get("JLINK_RTT_STREAM_PORT", "19052"))

SERVICE_NAME = os.environ.get("RS_SERVICE", "jlink-remote-server.service")
START_RTT_CLIENT = os.environ.get("START_RTT_CLIENT", "1") == "1"

SELF_ATTACH_GRACE_S = float(os.environ.get("SELF_ATTACH_GRACE_S", "3.0"))
WAITING_DEBOUNCE_S = float(os.environ.get("WAITING_DEBOUNCE_S", "1.0"))

LOG_DIR = os.environ.get("JLINK_RTT_LOG_DIR", f"/home/{RUN_AS_USER}/jlink-rtt")
os.makedirs(LOG_DIR, exist_ok=True)

JLINK_EXE = os.path.join(JLINK_DIR, "JLinkExe")
JLINK_RTTCLIENT = os.path.join(JLINK_DIR, "JLinkRTTClient")

RE_WAITING = re.compile(r"Waiting for client connections\.\.\.", re.IGNORECASE)
RE_CLIENT = re.compile(r"Client connected", re.IGNORECASE)

procs_lock = threading.Lock()
jlink_proc = None
rttc_proc = None
stop_flag = False

subscribers_lock = threading.Lock()
subscribers = []

rtt_log_file = None
last_self_attach_ts = 0.0


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def popen(cmd, **kw):
    log(f"EXEC: {cmd}")
    return subprocess.Popen(shlex.split(cmd), **kw)


def process_is_alive(p):
    return (p is not None) and (p.poll() is None)


def kill_quiet(p, name):
    if p is None:
        return
    try:
        if p.poll() is None:
            log(f"Killing {name} (pid={p.pid})")
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
    except Exception as e:
        log(f"Kill {name} error: {e}")


def wait_tcp(host, port, timeout_s=5.0, interval=0.1):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(interval)
    return False


def start_rtt_stream_server():
    if not RTT_STREAM_ENABLED:
        return

    def _acceptor():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", RTT_STREAM_PORT))
            srv.listen(5)
            srv.settimeout(1.0)
            log(f"RTT stream TCP on 0.0.0.0:{RTT_STREAM_PORT}")
            while not stop_flag:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    log(f"RTT stream accept error: {e}")
                    break
                conn.setblocking(True)
                with subscribers_lock:
                    subscribers.append(conn)
                log(f"Subscriber from {addr}")
        except Exception as e:
            log(f"RTT stream error: {e}")
        finally:
            try:
                srv.close()
            except Exception as e:
                log(f"RTT stream close error: {e}")

    t = threading.Thread(target=_acceptor, daemon=True)
    t.start()


def rtt_forwarder(proc, log_file):
    global subscribers
    try:
        if proc.stdout is None:
            return
        while not stop_flag:
            try:
                chunk = proc.stdout.read(1024)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    b = chunk.encode("utf-8", errors="replace")
                else:
                    b = chunk

                try:
                    log_file.write(
                        b if isinstance(b, str) else b.decode("utf-8", errors="replace")
                    )
                    log_file.flush()
                except Exception:
                    pass

                if RTT_STREAM_ENABLED:
                    with subscribers_lock:
                        dead = []
                        for s in list(subscribers):
                            try:
                                s.sendall(b)
                            except Exception:
                                try:
                                    s.close()
                                except Exception:
                                    pass
                                dead.append(s)
                        for d in dead:
                            try:
                                subscribers.remove(d)
                            except ValueError:
                                pass
            except Exception:
                time.sleep(0.05)
    finally:
        with subscribers_lock:
            for s in subscribers:
                try:
                    s.close()
                except Exception:
                    pass
            subscribers = []


def start_owner_and_rtt():
    global jlink_proc, rttc_proc, last_self_attach_ts
    with procs_lock:
        if process_is_alive(jlink_proc):
            log("JLinkExe already running")
            return

        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        jlink_log_path = os.path.join(LOG_DIR, f"jlink_{ts}.log")
        jlink_log = open(jlink_log_path, "w")

        jcmd = (
            f"{JLINK_EXE} "
            f"-Device {DEVICE} -If {IFACE} -Speed {SPEED_KHZ} -AutoConnect 1 "
            f"-ip {RS_HOST}:{RS_PORT} "
            f"-RTTTelnetPort {RTT_PORT}"
        )
        jlink_proc = popen(
            jcmd, stdout=jlink_log, stderr=subprocess.STDOUT, stdin=subprocess.PIPE
        )

        last_self_attach_ts = time.time()

        time.sleep(0.6)
        if not process_is_alive(jlink_proc):
            log("JLinkExe failed to start")
            try:
                jlink_log.close()
                with open(jlink_log_path, "r") as f:
                    err_output = f.read()
                    if err_output.strip():
                        log(f"JLinkExe output: {err_output[:500]}")
            except Exception:
                pass
            jlink_proc = None
            return

        if not wait_tcp("127.0.0.1", RTT_PORT, timeout_s=4.0):
            log(f"RTT port {RTT_PORT} not ready")
            return

        try:
            subprocess.run(
                ["pkill", "-f", f"JLinkRTTClient.*RTTTelnetPort {RTT_PORT}"],
                check=False,
            )
        except Exception:
            pass

        if START_RTT_CLIENT:
            global rtt_log_file
            rtt_log_path = os.path.join(LOG_DIR, f"rtt_{ts}.log")
            rtt_log_file = open(rtt_log_path, "a")
            rcmd = f"{JLINK_RTTCLIENT} -RTTTelnetPort {RTT_PORT}"
            rttc_proc = popen(
                rcmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
            )
            time.sleep(0.3)
            if process_is_alive(rttc_proc):
                log(f"RTT client attached on port {RTT_PORT}")
                try:
                    fwd = threading.Thread(
                        target=rtt_forwarder,
                        args=(rttc_proc, rtt_log_file),
                        daemon=True,
                    )
                    fwd.start()
                except Exception as e:
                    log(f"RTT forwarder thread error: {e}")

                def _heartbeat(proc):
                    try:
                        while (not stop_flag) and process_is_alive(proc):
                            try:
                                if proc.stdin:
                                    proc.stdin.write(b"Rasp Pi Heartbeat\n")
                                    proc.stdin.flush()
                                    time.sleep(0.5)
                                else:
                                    break
                            except Exception as e:
                                log(f"Heartbeat error: {e}")
                                break
                    finally:
                        try:
                            if proc.stdin:
                                proc.stdin.flush()
                        except Exception:
                            pass

                try:
                    hb = threading.Thread(
                        target=_heartbeat, args=(rttc_proc,), daemon=True
                    )
                    hb.start()
                except Exception as e:
                    log(f"Heartbeat thread error: {e}")
            else:
                log("RTT client failed to start")
        else:
            rttc_proc = None


def stop_owner_and_rtt(reason):
    global jlink_proc, rttc_proc, rtt_log_file
    with procs_lock:
        if process_is_alive(rttc_proc):
            try:
                if getattr(rttc_proc, "stdin", None):
                    try:
                        rttc_proc.stdin.close()
                    except Exception:
                        pass
            except Exception:
                pass
            kill_quiet(rttc_proc, "JLinkRTTClient")
        rttc_proc = None
        if rtt_log_file is not None:
            try:
                rtt_log_file.close()
            except Exception:
                pass
            rtt_log_file = None

        if process_is_alive(jlink_proc):
            log(f"Stopping JLinkExe: {reason}")
            try:
                if getattr(jlink_proc, "stdin", None):
                    try:
                        jlink_proc.stdin.close()
                    except Exception:
                        pass
            except Exception:
                pass
            kill_quiet(jlink_proc, "JLinkExe")
        jlink_proc = None


def journal_reader(service_name, out_queue):
    time.sleep(1.0)

    primed = subprocess.run(
        ["journalctl", "-u", service_name, "-n", "50", "-o", "cat"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for line in primed.stdout.splitlines():
        out_queue.put(("snapshot", line))

    while not stop_flag:
        try:
            p = subprocess.Popen(
                ["journalctl", "-u", service_name, "-f", "-o", "cat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in p.stdout:
                out_queue.put(("follow", line.rstrip("\n")))
            p.wait()
            time.sleep(0.5)
        except Exception as e:
            out_queue.put(("error", f"journalctl error: {e}"))
            time.sleep(1.0)


def state_machine():
    global last_self_attach_ts
    q = Queue()
    t = threading.Thread(target=journal_reader, args=(SERVICE_NAME, q), daemon=True)
    t.start()

    last_waiting_ts = 0.0
    snapshot_complete = False
    last_snapshot_waiting = 0.0

    while not stop_flag:
        try:
            kind, line = q.get(timeout=0.5)
        except Empty:
            if not snapshot_complete:
                snapshot_complete = True
                if last_snapshot_waiting > 0:
                    log("Snapshot shows probe available, attaching after debounce")
                    last_waiting_ts = last_snapshot_waiting

            if (last_waiting_ts > 0) and (
                (time.time() - last_waiting_ts) > WAITING_DEBOUNCE_S
            ):
                if not process_is_alive(jlink_proc):
                    start_owner_and_rtt()
                last_waiting_ts = 0.0
            continue

        client_hit = bool(RE_CLIENT.search(line))
        waiting_hit = bool(RE_WAITING.search(line))

        if client_hit:
            if not snapshot_complete:
                log(f"RemoteServer (snapshot): {line}")
                continue

            now = time.time()
            if (now - last_self_attach_ts) <= SELF_ATTACH_GRACE_S:
                log(f"RemoteServer (grace): {line}")
                continue

            log(f"RemoteServer: {line}")
            stop_owner_and_rtt("External client connected")

        elif waiting_hit:
            log(f"RemoteServer: {line}")
            if not snapshot_complete:
                last_snapshot_waiting = time.time()
            else:
                last_waiting_ts = time.time()


def handle_signals():
    def _sig(signum, frame):
        global stop_flag
        stop_flag = True
        log(f"Signal {signum} received, shutting down")
        stop_owner_and_rtt("shutdown")
        time.sleep(0.2)
        sys.exit(0)

    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, _sig)


def check_binaries():
    for path in (JLINK_EXE, JLINK_RTTCLIENT):
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            log(f"ERROR: Not executable: {path}")
            sys.exit(2)
    if not shutil_which("journalctl"):
        log("ERROR: journalctl not found")
        sys.exit(2)


def shutil_which(cmd):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, cmd)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def main():
    handle_signals()
    check_binaries()
    log(f"J-Link RTT supervisor starting (RS={RS_HOST}:{RS_PORT}, RTT={RTT_PORT})")
    log(f"Logs: {LOG_DIR}")
    start_rtt_stream_server()
    try:
        state_machine()
    finally:
        stop_owner_and_rtt("exit")


if __name__ == "__main__":
    main()
