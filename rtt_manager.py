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

# Config (env)
RUN_AS_USER = os.environ.get("RUN_AS_USER", "aruw")
JLINK_DIR = os.environ.get("JLINK_DIR", f"/home/{RUN_AS_USER}/JLink_Linux_V812g_arm")

DEVICE = os.environ.get("JLINK_DEVICE", "STM32F427II")
IFACE = os.environ.get("JLINK_IFACE", "SWD")
SPEED_KHZ = int(os.environ.get("JLINK_SPEED_KHZ", "4000"))

RS_HOST = os.environ.get("JLINK_RS_HOST", "127.0.0.1")
RS_PORT = int(os.environ.get("JLINK_RS_PORT", "19020"))  # J-Link Remote Server
RTT_PORT = int(os.environ.get("JLINK_RTT_PORT", "19051"))  # Local RTT telnet port

# Optional read-only RTT stream for local subscribers
RTT_STREAM_ENABLED = os.environ.get("JLINK_RTT_STREAM_ENABLED", "1") == "1"
# 'tcp' or 'udp' (tcp: multi-client read-only server; udp: datagrams sent to 127.0.0.1:RTT_STREAM_PORT)
RTT_STREAM_PROTO = os.environ.get("JLINK_RTT_STREAM_PROTO", "tcp").lower()
RTT_STREAM_PORT = int(os.environ.get("JLINK_RTT_STREAM_PORT", "19052"))

SERVICE_NAME = os.environ.get("RS_SERVICE", "jlink-remote-server.service")
START_RTT_CLIENT = os.environ.get("START_RTT_CLIENT", "1") == "1"  # 0 to disable

# Self-attach grace window (seconds): ignore immediate "Client connected" events
SELF_ATTACH_GRACE_S = float(os.environ.get("SELF_ATTACH_GRACE_S", "3.0"))

# Debounce after "Waiting..." (seconds) before attempting attach
WAITING_DEBOUNCE_S = float(os.environ.get("WAITING_DEBOUNCE_S", "1.0"))

LOG_DIR = os.environ.get("JLINK_RTT_LOG_DIR", f"/home/{RUN_AS_USER}/jlink-rtt")
os.makedirs(LOG_DIR, exist_ok=True)
# Binaries
JLINK_EXE = os.path.join(JLINK_DIR, "JLinkExe")
JLINK_RTTCLIENT = os.path.join(JLINK_DIR, "JLinkRTTClient")

# Journal patterns
RE_WAITING = re.compile(r"Waiting for client connections\.\.\.", re.IGNORECASE)
RE_CLIENT = re.compile(r"Client connected", re.IGNORECASE)

# Globals
procs_lock = threading.Lock()
jlink_proc = None
rttc_proc = None
stop_flag = False

# RTT stream subscribers (TCP sockets) or UDP sender socket
subscribers_lock = threading.Lock()
subscribers = []  # list of socket.socket objects (TCP)
udp_sender = None

# RTT log file used for forwarding
rtt_log_file = None

# Last local JLinkExe spawn timestamp (for grace checks)
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
    """Start a background RTT stream acceptor or UDP sender."""
    if not RTT_STREAM_ENABLED:
        return

    if RTT_STREAM_PROTO == "udp":
        # UDP sender socket (no bind required for sending to localhost)
        global udp_sender
        try:
            udp_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            log(f"RTT stream UDP sender prepared -> 127.0.0.1:{RTT_STREAM_PORT}")
        except Exception as e:
            log(f"RTT stream: failed to create UDP sender: {e}")
        return

    # TCP mode
    def _acceptor():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", RTT_STREAM_PORT))
            srv.listen(5)
            srv.settimeout(1.0)
            log(f"RTT stream TCP listening on 0.0.0.0:{RTT_STREAM_PORT}")
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
                log(f"Subscriber connected from {addr}")
        except Exception as e:
            log(f"RTT stream server error: {e}")
        finally:
            try:
                srv.close()
            except Exception:
                pass

    t = threading.Thread(target=_acceptor, daemon=True)
    t.start()


def rtt_forwarder(proc, log_file):
    """Read RTT client stdout, write to log, and forward to subscribers."""
    global subscribers, udp_sender
    try:
        if proc.stdout is None:
            return
        # Read and forward bytes
        while not stop_flag:
            try:
                chunk = proc.stdout.read(1024)
                if not chunk:
                    break
                # Ensure bytes
                if isinstance(chunk, str):
                    b = chunk.encode("utf-8", errors="replace")
                else:
                    b = chunk

                # Write to log
                try:
                    log_file.write(
                        b if isinstance(b, str) else b.decode("utf-8", errors="replace")
                    )
                    log_file.flush()
                except Exception:
                    # ignore logging issues
                    pass

                # Forward to subscribers
                if RTT_STREAM_ENABLED:
                    if RTT_STREAM_PROTO == "udp":
                        try:
                            if udp_sender:
                                udp_sender.sendto(b, ("127.0.0.1", RTT_STREAM_PORT))
                        except Exception:
                            pass
                    else:
                        # TCP: send to all connected subscriber sockets
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
                # back off a bit on unexpected read issues
                time.sleep(0.05)
    finally:
        # Close subscribers
        with subscribers_lock:
            for s in subscribers:
                try:
                    s.close()
                except Exception:
                    pass
            subscribers = []
        try:
            if udp_sender:
                udp_sender.close()
        except Exception:
            pass


def start_owner_and_rtt():
    """Start JLinkExe and optionally an RTT client."""
    global jlink_proc, rttc_proc, last_self_attach_ts
    with procs_lock:
        if process_is_alive(jlink_proc):
            log("JLinkExe already running; not starting another.")
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
        jlink_proc = popen(jcmd, stdout=jlink_log, stderr=subprocess.STDOUT)

        # Record launch time; immediate 'Client connected' may be local.
        last_self_attach_ts = time.time()

        time.sleep(0.6)
        if not process_is_alive(jlink_proc):
            log("JLinkExe failed to start (likely because Ozone owns the probe).")
            jlink_proc = None
            return

        # Wait for RTT port
        if not wait_tcp("127.0.0.1", RTT_PORT, timeout_s=4.0):
            log(f"RTT port {RTT_PORT} not listening yet; will not spawn RTT client.")
            return

        # Kill stale RTT clients
        try:
            subprocess.run(
                ["pkill", "-f", f"JLinkRTTClient.*RTTTelnetPort {RTT_PORT}"],
                check=False,
            )
        except Exception:
            pass

        if START_RTT_CLIENT:
            # Open RTT log and forward client stdout
            global rtt_log_file
            rtt_log_path = os.path.join(LOG_DIR, f"rtt_{ts}.log")
            rtt_log_file = open(rtt_log_path, "a")
            rcmd = f"{JLINK_RTTCLIENT} -RTTTelnetPort {RTT_PORT}"
            # Capture stdout and open stdin so a heartbeat can be sent
            rttc_proc = popen(
                rcmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
            )
            time.sleep(0.3)
            if process_is_alive(rttc_proc):
                log(f"RTT client attached on port {RTT_PORT}.")
                # Start forwarder thread to relay RTT output
                try:
                    fwd = threading.Thread(
                        target=rtt_forwarder,
                        args=(rttc_proc, rtt_log_file),
                        daemon=True,
                    )
                    fwd.start()
                except Exception as e:
                    log(f"Failed to start RTT forwarder thread: {e}")

                # Start heartbeat thread: send "1" every 0.5s while this process owns the RTT client
                def _heartbeat(proc):
                    try:
                        while (not stop_flag) and process_is_alive(proc):
                            try:
                                if proc.stdin:
                                    # First beat
                                    proc.stdin.write(b"Rasp Pi Heartbeat\n")
                                    proc.stdin.flush()
                                    time.sleep(0.5) 
                                    
                                else:
                                    log("proc.stdin false")
                                    break
                            except Exception as e:
                                # stop heartbeat if writing fails
                                log(f"Heartbeat Failure: {e}")
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
                    log(f"Failed to start RTT heartbeat thread: {e}")
            else:
                log("RTT client failed to start (port taken or other issue).")
        else:
            rttc_proc = None
            log("START_RTT_CLIENT=0, not launching RTT client.")


def stop_owner_and_rtt(reason):
    """Stop JLinkExe and RTT client."""
    global jlink_proc, rttc_proc, rtt_log_file
    with procs_lock:
        if process_is_alive(rttc_proc):
            # close stdin to help the client exit cleanly
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
        # Close RTT log file if we opened one for forwarding
        if rtt_log_file is not None:
            try:
                rtt_log_file.close()
            except Exception:
                pass
            rtt_log_file = None

        if process_is_alive(jlink_proc):
            log(f"Stopping JLinkExe: {reason}")
            kill_quiet(jlink_proc, "JLinkExe")
        jlink_proc = None


def journal_reader(service_name, out_queue):
    """
    Follow the journal for the Remote Server service and push lines to a queue.
    """
    # Prime recent lines
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
    """Reactions:
    - 'Client connected' -> if within self-attach grace window, ignore; otherwise stop owner.
    - 'Waiting for client connections...' -> after debounce, start owner+RTT if not running.
    """
    global last_self_attach_ts
    q = Queue()
    t = threading.Thread(target=journal_reader, args=(SERVICE_NAME, q), daemon=True)
    t.start()

    last_waiting_ts = 0.0

    while not stop_flag:
        try:
            kind, line = q.get(timeout=0.5)
        except Empty:
            # Debounced attach after 'Waiting...'
            if (last_waiting_ts > 0) and (
                (time.time() - last_waiting_ts) > WAITING_DEBOUNCE_S
            ):
                if not process_is_alive(jlink_proc):
                    start_owner_and_rtt()
                last_waiting_ts = 0.0
            continue

        # Parse
        client_hit = bool(RE_CLIENT.search(line))
        waiting_hit = bool(RE_WAITING.search(line))

        if client_hit:
            now = time.time()
            # If JLinkExe was just spawned, this 'Client connected' is likely from the spawn; ignore it.
            if (now - last_self_attach_ts) <= SELF_ATTACH_GRACE_S:
                log(f"RemoteServer (grace): {line}")
                # After the grace period, future client connections will stop the owner.
                continue

            # Otherwise an external client connected; stop the owner.
            log(f"RemoteServer: {line}")
            stop_owner_and_rtt("Remote Server shows 'Client connected' (not local)")

        elif waiting_hit:
            log(f"RemoteServer: {line}")
            last_waiting_ts = (
                time.time()
            )  # after debounce, will call start_owner_and_rtt()


def handle_signals():
    def _sig(signum, frame):
        global stop_flag
        stop_flag = True
        log(f"Signal {signum} received; shutting down...")
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
        log("ERROR: 'journalctl' not found in PATH.")
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
    log(
        f"Starting J-Link RTT supervisor "
        f"(service='{SERVICE_NAME}', RS={RS_HOST}:{RS_PORT}, RTT={RTT_PORT}, "
        f"SELF_ATTACH_GRACE_S={SELF_ATTACH_GRACE_S})"
    )
    log(f"Logs in: {LOG_DIR}")
    # Start the RTT stream server/sender (if enabled). This runs in background.
    start_rtt_stream_server()
    try:
        state_machine()
    finally:
        stop_owner_and_rtt("exit")


if __name__ == "__main__":
    main()