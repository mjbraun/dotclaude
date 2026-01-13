# ABOUTME: TCP proxy for Sofabaton X1S hub traffic capture
# ABOUTME: Intercepts app<->hub communication with mDNS advertisement

import json
import logging
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Callable, Tuple

log = logging.getLogger(__name__)

# Protocol constants
SYNC0, SYNC1 = 0xA5, 0x5A
OP_CALL_ME = 0x0CC3

# Known opcodes
OPNAMES = {
    0x0CC3: "CALL_ME",
    0x000A: "REQ_DEVICES",
    0x003A: "REQ_ACTIVITIES",
    0x023C: "REQ_BUTTONS",
    0x025C: "REQ_COMMANDS",
    0x023F: "REQ_ACTIVATE",
    0x0023: "FIND_REMOTE",
    0x024D: "REQ_MACRO_LABELS",
    0x3801: "UPDATE_DEVICE",
    0xD50B: "CATALOG_ROW_DEVICE",
    0xD53B: "CATALOG_ROW_ACTIVITY",
    0x7B0B: "X1_DEVICE",
    0x7B3B: "X1_ACTIVITY",
    0x0160: "ACK_READY",
    0x0C3D: "MARKER",
}


@dataclass
class HubFrame:
    """A captured Sofabaton protocol frame."""
    id: str
    timestamp: str
    direction: str  # "A→H" (app to hub) or "H→A" (hub to app)
    opcode: int
    opcode_name: str
    raw_hex: str
    payload_hex: str
    raw_length: int
    payload_length: int


class HubFrameStorage:
    """Thread-safe storage for captured hub frames."""

    def __init__(self, max_size: int = 1000):
        self._frames: List[HubFrame] = []
        self._lock = threading.Lock()
        self._max_size = max_size
        self._counter = 0

    def add(self, direction: str, opcode: int, raw: bytes, payload: bytes) -> str:
        """Add a frame and return its ID."""
        with self._lock:
            self._counter += 1
            frame_id = f"hf-{self._counter:06d}"

            frame = HubFrame(
                id=frame_id,
                timestamp=datetime.now().isoformat(),
                direction=direction,
                opcode=opcode,
                opcode_name=OPNAMES.get(opcode, f"OP_{opcode:04X}"),
                raw_hex=raw.hex(),
                payload_hex=payload.hex(),
                raw_length=len(raw),
                payload_length=len(payload),
            )

            self._frames.append(frame)

            # Trim if over max
            if len(self._frames) > self._max_size:
                self._frames = self._frames[-self._max_size:]

            return frame_id

    def list(self, limit: int = 50, direction_filter: Optional[str] = None) -> List[HubFrame]:
        """List frames, newest first."""
        with self._lock:
            frames = list(reversed(self._frames))
            if direction_filter:
                frames = [f for f in frames if f.direction == direction_filter]
            return frames[:limit]

    def get(self, frame_id: str) -> Optional[HubFrame]:
        """Get a specific frame by ID."""
        with self._lock:
            for f in self._frames:
                if f.id == frame_id:
                    return f
            return None

    def search(self, query: str) -> List[HubFrame]:
        """Search frames by opcode name or hex content."""
        query_lower = query.lower()
        with self._lock:
            return [
                f for f in reversed(self._frames)
                if query_lower in f.opcode_name.lower()
                or query_lower in f.raw_hex.lower()
                or query_lower in f.payload_hex.lower()
            ]

    def clear(self) -> int:
        """Clear all frames and return count."""
        with self._lock:
            count = len(self._frames)
            self._frames.clear()
            return count

    def __len__(self) -> int:
        with self._lock:
            return len(self._frames)


def checksum(data: bytes) -> int:
    """Calculate 8-bit checksum."""
    return sum(data) & 0xFF


def route_local_ip(peer_ip: str) -> str:
    """Get local IP for reaching a peer."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((peer_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class Deframer:
    """Extract protocol frames from TCP stream."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes) -> List[Tuple[int, bytes, bytes]]:
        """Feed data and return list of (opcode, raw_frame, payload) tuples."""
        out = []
        if not data:
            return out

        self.buf.extend(data)

        if len(self.buf) > 1_000_000:
            del self.buf[:500_000]

        while True:
            start = self.buf.find(bytes([SYNC0, SYNC1]))
            if start < 0:
                self.buf.clear()
                break

            if start > 0:
                del self.buf[:start]

            if len(self.buf) < 5:
                break

            next_sync = self.buf.find(bytes([SYNC0, SYNC1]), 2)
            if next_sync != -1:
                cand = bytes(self.buf[:next_sync])
                if cand and cand[-1] == (checksum(cand[:-1]) & 0xFF):
                    opcode = (cand[2] << 8) | cand[3]
                    payload = cand[4:-1]
                    out.append((opcode, cand, payload))
                    del self.buf[:next_sync]
                    continue
                del self.buf[0]
                continue

            cand = bytes(self.buf)
            if len(cand) >= 5 and cand[-1] == (checksum(cand[:-1]) & 0xFF):
                opcode = (cand[2] << 8) | cand[3]
                payload = cand[4:-1]
                out.append((opcode, cand, payload))
                self.buf.clear()
            break

        return out


class HubProxy:
    """TCP/UDP proxy between Sofabaton app and hub with mDNS advertisement."""

    def __init__(
        self,
        real_hub_ip: str,
        real_hub_udp_port: int = 8102,
        proxy_udp_port: int = 8102,
        tcp_listen_port: int = 8200,
        storage: Optional[HubFrameStorage] = None,
    ):
        self.real_hub_ip = real_hub_ip
        self.real_hub_udp_port = real_hub_udp_port
        self.proxy_udp_port = proxy_udp_port
        self.tcp_listen_port = tcp_listen_port
        self.storage = storage or HubFrameStorage()

        self._stop = threading.Event()
        self._udp_sock: Optional[socket.socket] = None
        self._tcp_listen_sock: Optional[socket.socket] = None
        self._hub_sock: Optional[socket.socket] = None
        self._app_sock: Optional[socket.socket] = None

        self._hub_deframer = Deframer()
        self._app_deframer = Deframer()

        self._threads: List[threading.Thread] = []
        self._mdns_info = None
        self._zc = None

        self.local_ip = route_local_ip(real_hub_ip)

    def _start_mdns(self) -> bool:
        """Start mDNS advertisement so the app can discover this proxy."""
        try:
            from zeroconf import Zeroconf, ServiceInfo, IPVersion

            ip_bytes = socket.inet_aton(self.local_ip)
            service_type = "_x1hub._udp.local."
            instance = "X1-HUB-PROXY"
            host = f"{instance}.local."

            info = ServiceInfo(
                type_=service_type,
                name=f"{instance}.{service_type}",
                addresses=[ip_bytes],
                port=self.proxy_udp_port,
                properties={
                    b"MAC": b"000000000000",
                    b"NAME": b"X1S HUB PROXY",
                    b"AVER": b"5",
                    b"NO": b"20221120",
                    b"HVER": b"2",
                },
                server=host,
            )

            self._zc = Zeroconf(ip_version=IPVersion.V4Only)
            self._zc.register_service(info)
            self._mdns_info = info

            log.info(f"[mDNS] Registered {info.name} at {self.local_ip}:{self.proxy_udp_port}")
            return True
        except ImportError:
            log.warning("zeroconf not installed - mDNS advertisement disabled")
            return False
        except Exception as e:
            log.error(f"Failed to start mDNS: {e}")
            return False

    def _stop_mdns(self):
        """Stop mDNS advertisement."""
        if self._zc and self._mdns_info:
            try:
                self._zc.unregister_service(self._mdns_info)
                self._zc.close()
            except Exception as e:
                log.warning(f"Error stopping mDNS: {e}")
        self._zc = None
        self._mdns_info = None

    def _build_call_me_frame(self, ip: str, port: int) -> bytes:
        """Build a CALL_ME frame to send to the hub."""
        payload = b"\x00" * 6 + socket.inet_aton(ip) + struct.pack(">H", port)
        frame = bytes([SYNC0, SYNC1, 0x0C, 0xC3]) + payload
        return frame + bytes([checksum(frame)])

    def _handle_udp(self) -> None:
        """Handle UDP CALL_ME requests."""
        try:
            self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp_sock.bind(("0.0.0.0", self.proxy_udp_port))
            self._udp_sock.setblocking(False)
        except OSError as e:
            log.error(f"Cannot bind UDP port {self.proxy_udp_port}: {e}")
            return

        log.info(f"[UDP] Listening on port {self.proxy_udp_port}")

        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([self._udp_sock], [], [], 0.5)
                if not readable:
                    continue

                data, addr = self._udp_sock.recvfrom(1024)
                log.info(f"[UDP] Received {len(data)}B from {addr}")

                if len(data) >= 4 and data[0] == SYNC0 and data[1] == SYNC1:
                    opcode = (data[2] << 8) | data[3]
                    if opcode == OP_CALL_ME:
                        if len(data) >= 18:
                            caller_ip = socket.inet_ntoa(data[10:14])
                            caller_port = struct.unpack(">H", data[14:16])[0]
                            log.info(f"[UDP] CALL_ME from {caller_ip}:{caller_port}")

                            # If from app, connect to hub and start bridging
                            if addr[0] != self.real_hub_ip:
                                log.info(f"[UDP] App discovered us, initiating TCP connection")
                                # Send CALL_ME to real hub
                                call_me = self._build_call_me_frame(self.local_ip, self.tcp_listen_port)
                                hub_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                hub_udp.sendto(call_me, (self.real_hub_ip, self.real_hub_udp_port))
                                hub_udp.close()

            except Exception as e:
                if not self._stop.is_set():
                    log.exception(f"UDP error: {e}")

    def _handle_tcp_accept(self) -> None:
        """Accept TCP connections from app."""
        try:
            self._tcp_listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_listen_sock.bind(("0.0.0.0", self.tcp_listen_port))
            self._tcp_listen_sock.listen(1)
            self._tcp_listen_sock.setblocking(False)
        except OSError as e:
            log.error(f"Cannot bind TCP port {self.tcp_listen_port}: {e}")
            return

        log.info(f"[TCP] Listening on port {self.tcp_listen_port}")

        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([self._tcp_listen_sock], [], [], 0.5)
                if not readable:
                    continue

                conn, addr = self._tcp_listen_sock.accept()
                log.info(f"[TCP] App connected from {addr}")

                # Connect to real hub
                hub_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    hub_conn.connect((self.real_hub_ip, self.tcp_listen_port))
                    log.info(f"[TCP] Connected to hub at {self.real_hub_ip}:{self.tcp_listen_port}")
                except Exception as e:
                    log.error(f"[TCP] Failed to connect to hub: {e}")
                    conn.close()
                    continue

                self._app_sock = conn
                self._hub_sock = hub_conn

                # Reset deframers
                self._hub_deframer = Deframer()
                self._app_deframer = Deframer()

                t = threading.Thread(target=self._bridge_tcp, daemon=True)
                t.start()
                self._threads.append(t)

            except Exception as e:
                if not self._stop.is_set():
                    log.exception(f"TCP accept error: {e}")

    def _bridge_tcp(self) -> None:
        """Bridge TCP traffic between app and hub."""
        app = self._app_sock
        hub = self._hub_sock

        if not app or not hub:
            return

        app.setblocking(False)
        hub.setblocking(False)

        log.info("[BRIDGE] Starting traffic relay")

        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([app, hub], [], [], 0.5)

                for sock in readable:
                    try:
                        data = sock.recv(4096)
                    except (BlockingIOError, ConnectionError):
                        continue

                    if not data:
                        log.info("[BRIDGE] Connection closed")
                        return

                    if sock == app:
                        direction = "A→H"
                        deframer = self._app_deframer
                        dest = hub
                    else:
                        direction = "H→A"
                        deframer = self._hub_deframer
                        dest = app

                    # Parse and store frames
                    frames = deframer.feed(data)
                    for opcode, raw, payload in frames:
                        frame_id = self.storage.add(direction, opcode, raw, payload)
                        name = OPNAMES.get(opcode, f"OP_{opcode:04X}")
                        log.info(f"[{direction}] {frame_id} {name} (0x{opcode:04X}) len={len(raw)}")

                    # Forward data
                    try:
                        dest.sendall(data)
                    except Exception as e:
                        log.error(f"[BRIDGE] Send error: {e}")
                        return

            except Exception as e:
                if not self._stop.is_set():
                    log.exception(f"Bridge error: {e}")
                return

        log.info("[BRIDGE] Stopped")

    @property
    def is_running(self) -> bool:
        """Check if proxy is running."""
        return not self._stop.is_set() and any(t.is_alive() for t in self._threads)

    def start(self) -> None:
        """Start the proxy with mDNS advertisement."""
        self._stop.clear()

        log.info(f"Starting hub proxy for {self.real_hub_ip}")

        # Start mDNS first
        self._start_mdns()

        # Start UDP handler
        t = threading.Thread(target=self._handle_udp, daemon=True)
        t.start()
        self._threads.append(t)

        # Start TCP listener
        t = threading.Thread(target=self._handle_tcp_accept, daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self) -> None:
        """Stop the proxy."""
        log.info("Stopping hub proxy...")
        self._stop.set()

        self._stop_mdns()

        for sock in [self._udp_sock, self._tcp_listen_sock, self._hub_sock, self._app_sock]:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        for t in self._threads:
            t.join(timeout=2.0)

        self._threads.clear()
