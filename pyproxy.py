#!/usr/bin/env python3
"""
pyproxy - route the TCP traffic of every Python process through a proxy list.

It works by monkeypatching socket.socket.connect (plus asyncio's sock_connect),
so anything built on sockets (requests, urllib, aiohttp, httpx, websockets,
...) goes through the proxy. No third-party dependencies. Supports SOCKS5 and
HTTP CONNECT proxies, rotating between them and skipping dead ones.

Usage:
    python pyproxy.py install proxies.txt   # every future python process uses it
    python pyproxy.py uninstall             # undo
    python pyproxy.py status
    python pyproxy.py test [proxies.txt]    # check each proxy, show exit IPs
    python pyproxy.py run script.py [args]  # proxy one script only

Proxy list format, one per line ('#' comments allowed):
    host:port
    host:port:user:pass
    user:pass@host:port
    socks5://user:pass@host:port
    http://user:pass@host:port
    [2001:db8::1]:1080                     # IPv6 hosts go in brackets
'https://' entries are treated as 'http://' (CONNECT); TLS to the proxy
itself is not supported.

Environment variables (override the installed config):
    PYPROXY_LIST      path to proxy list file
    PYPROXY_DEFAULT   scheme for bare entries: socks5 (default) or http
    PYPROXY_MODE      rotate (new proxy per connection, default) | sticky
    PYPROXY_DISABLE   set to 1 to bypass the proxy for this process

Limitations: TCP only (UDP/QUIC is not proxied). Most libraries resolve
hostnames locally before connecting, so DNS lookups are usually not tunnelled.
A failed proxy raises a connection error instead of retrying transparently;
the proxy is then skipped for a while, so the caller's next attempt uses
another one.
"""
import base64
import errno
import importlib.abc
import ipaddress
import itertools
import os
import random
import socket
import struct
import sys
import threading
import time

HOME = os.path.join(os.path.expanduser("~"), ".pyproxy")
CONFIG = os.path.join(HOME, "proxies.txt")
PTH_NAME = "pyproxy_boot.pth"
HANDSHAKE_TIMEOUT = 10
DEAD_COOLDOWN = 60

# If another copy of this module already patched socket (e.g. the installed
# one loaded via .pth, and this file is being run as a script), grab the real
# originals instead of the other copy's patched functions.
_orig_connect = getattr(socket.socket.connect, "_pyproxy_orig", socket.socket.connect)
_orig_connect_ex = getattr(socket.socket.connect_ex, "_pyproxy_orig", socket.socket.connect_ex)
_pool = None


class Proxy:
    def __init__(self, scheme, host, port, user=None, password=None):
        self.scheme, self.host, self.port = scheme, host, int(port)
        self.user, self.password = user, password
        self.dead_until = 0.0

    def __repr__(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


def _split_host(s):
    """Split 'host:rest' or '[v6host]:rest' into (host, rest)."""
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        if not rest.startswith(":"):
            raise ValueError(f"bad proxy address: {s}")
        return host, rest[1:]
    host, _, rest = s.partition(":")
    return host, rest


def parse_proxy(line, default="socks5"):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    scheme = default
    if "://" in line:
        scheme, line = line.split("://", 1)
    scheme = scheme.lower()
    if scheme in ("socks5h", "socks"):
        scheme = "socks5"
    if scheme == "https":
        scheme = "http"
    if scheme not in ("socks5", "http"):
        raise ValueError(f"unsupported scheme: {scheme}")
    user = password = None
    if "@" in line:
        cred, line = line.rsplit("@", 1)
        user, _, password = cred.partition(":")
        host, port = _split_host(line)
    else:
        host, rest = _split_host(line)
        port, _, cred = rest.partition(":")
        if cred:
            user, sep, password = cred.partition(":")
            if not sep:
                raise ValueError(f"bad proxy line: {line}")
    if not host:
        raise ValueError(f"bad proxy line: {line}")
    return Proxy(scheme, host, port, user, password)  # int(port) may raise ValueError


def load_proxies(path, default=None):
    default = default or os.environ.get("PYPROXY_DEFAULT", "socks5")
    proxies = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                p = parse_proxy(line, default)
            except ValueError:
                continue
            if p:
                proxies.append(p)
    return proxies


class Pool:
    def __init__(self, proxies, mode="rotate"):
        self.proxies = proxies
        self.mode = mode
        self.lock = threading.Lock()
        self.cycle = itertools.cycle(random.sample(proxies, len(proxies)))
        self.sticky = None

    def get(self):
        with self.lock:
            now = time.time()
            if self.mode == "sticky" and self.sticky and self.sticky.dead_until < now:
                return self.sticky
            for _ in range(len(self.proxies)):
                p = next(self.cycle)
                if p.dead_until < now:
                    if self.mode == "sticky":
                        self.sticky = p
                    return p
            # everything is marked dead: try whichever comes back soonest
            return min(self.proxies, key=lambda p: p.dead_until, default=None)

    def mark_dead(self, proxy):
        proxy.dead_until = time.time() + DEAD_COOLDOWN


# --------------------------------------------------------------- handshakes

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("proxy closed connection during handshake")
        buf += chunk
    return buf


def _socks5(sock, proxy, host, port):
    auth = proxy.user is not None
    sock.sendall(b"\x05\x02\x00\x02" if auth else b"\x05\x01\x00")
    ver, method = _recv_exact(sock, 2)
    if ver != 5:
        raise ConnectionError("not a SOCKS5 proxy")
    if method == 2 and auth:
        u, p = proxy.user.encode(), (proxy.password or "").encode()
        if len(u) > 255 or len(p) > 255:
            raise ConnectionError("SOCKS5 username/password longer than 255 bytes")
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if _recv_exact(sock, 2)[1] != 0:
            raise ConnectionError("proxy auth failed")
    elif method != 0:
        raise ConnectionError("proxy rejected auth methods")

    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        # A hostname: let the proxy resolve it.
        try:
            name = host.encode("idna")
        except UnicodeError as e:
            raise OSError(errno.EINVAL, f"invalid hostname {host!r}") from e
        if len(name) > 255:
            raise OSError(errno.EINVAL, f"hostname too long: {host!r}")
        addr = b"\x03" + bytes([len(name)]) + name
    sock.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", port))
    _, rep, _, atyp = _recv_exact(sock, 4)
    if rep != 0:
        raise ConnectionRefusedError(f"SOCKS5 connect failed (code {rep})")
    skip = {1: 4, 4: 16}.get(atyp)
    if skip is None:
        skip = _recv_exact(sock, 1)[0]
    _recv_exact(sock, skip + 2)


def _http_connect(sock, proxy, host, port):
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if proxy.user is not None:
        token = base64.b64encode(f"{proxy.user}:{proxy.password or ''}".encode()).decode()
        req += f"Proxy-Authorization: Basic {token}\r\n"
    sock.sendall((req + "\r\n").encode())
    resp = b""
    # Read byte by byte so we never swallow data belonging to the tunnel.
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("proxy closed connection during handshake")
        resp += chunk
        if len(resp) > 16384:
            raise ConnectionError("oversized proxy response")
    first_line = resp.split(b"\r\n", 1)[0]
    status = first_line.split()
    if len(status) < 2 or status[1] != b"200":
        raise ConnectionRefusedError(f"HTTP proxy refused: {first_line!r}")


# --------------------------------------------------------------- the patch

def _is_local(host):
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return host.lower() == "localhost"
    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified


def _should_proxy(sock, address):
    return (_pool is not None
            and sock.type == socket.SOCK_STREAM
            and sock.family in (socket.AF_INET, socket.AF_INET6)
            and isinstance(address, tuple)
            and not _is_local(address[0]))


def _connect_via(sock, proxy, host, port):
    # Resolve the proxy with the real resolver, connect the *same* socket to it.
    infos = socket.getaddrinfo(proxy.host, proxy.port, sock.family, socket.SOCK_STREAM)
    if not infos:
        raise OSError(errno.ENETUNREACH, "cannot reach proxy over this address family")
    _orig_connect(sock, infos[0][4])
    if proxy.scheme == "socks5":
        _socks5(sock, proxy, host, port)
    else:
        _http_connect(sock, proxy, host, port)


def _patched_connect(self, address):
    if not _should_proxy(self, address):
        return _orig_connect(self, address)
    host, port = address[0], address[1]

    proxy = _pool.get()
    if proxy is None:
        raise ConnectionError("no usable proxy")
    old_timeout = self.gettimeout()
    # The handshake is done in blocking mode, even for non-blocking sockets,
    # but never waits longer than the caller's own timeout.
    if old_timeout:
        self.settimeout(min(old_timeout, HANDSHAKE_TIMEOUT))
    else:
        self.settimeout(HANDSHAKE_TIMEOUT)
    try:
        _connect_via(self, proxy, host, port)
    except OSError:
        # A failed socket can't be reused, so surface the error; the dead
        # proxy is skipped for a while and the caller's retry gets another.
        _pool.mark_dead(proxy)
        raise
    finally:
        self.settimeout(old_timeout)


def _patched_connect_ex(self, address):
    try:
        _patched_connect(self, address)
        return 0
    except OSError as e:
        return e.errno or errno.ECONNREFUSED


_patched_connect._pyproxy_orig = _orig_connect
_patched_connect._pyproxy_should = _should_proxy
_patched_connect_ex._pyproxy_orig = _orig_connect_ex


# ----------------------------------------------------------------- asyncio
# Windows' default (Proactor) event loop connects with ConnectEx and never
# calls socket.connect, and the selector loop would block on our handshake.
# So asyncio's sock_connect is wrapped to run the proxied connect in a thread.
# The wrapper looks up whatever patch is currently on socket.socket.connect,
# so it keeps working if another copy of this module is active.

_LOOP_CLASSES = {
    "asyncio.proactor_events": "BaseProactorEventLoop",
    "asyncio.selector_events": "BaseSelectorEventLoop",
}


def _wrap_loop_class(module, cls_name):
    cls = getattr(module, cls_name, None)
    if cls is None or getattr(cls.sock_connect, "_pyproxy_wrapped", False):
        return
    orig = cls.sock_connect

    async def sock_connect(self, sock, address):
        should = getattr(socket.socket.connect, "_pyproxy_should", None)
        if should is not None and should(sock, address):
            return await self.run_in_executor(None, sock.connect, address)
        return await orig(self, sock, address)

    sock_connect._pyproxy_wrapped = True
    cls.sock_connect = sock_connect


class _AsyncioHook(importlib.abc.MetaPathFinder):
    """Wraps the event loop classes as soon as asyncio imports them, so
    asyncio isn't imported (and startup isn't slowed) in every process."""
    _pyproxy_hook = True

    def find_spec(self, name, path, target=None):
        if name not in _LOOP_CLASSES:
            return None
        for finder in sys.meta_path:
            if finder is self or getattr(finder, "_pyproxy_hook", False) \
                    or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(name, path, target)
            if spec is not None:
                break
        else:
            return None
        exec_module = spec.loader.exec_module

        def patched_exec(module):
            exec_module(module)
            _wrap_loop_class(module, _LOOP_CLASSES[name])

        spec.loader.exec_module = patched_exec
        return spec


def _hook_asyncio():
    for name, cls_name in _LOOP_CLASSES.items():
        if name in sys.modules:
            _wrap_loop_class(sys.modules[name], cls_name)
    if not any(getattr(f, "_pyproxy_hook", False) for f in sys.meta_path):
        sys.meta_path.insert(0, _AsyncioHook())


# ---------------------------------------------------------------- activate

def activate(proxies, mode="rotate"):
    global _pool
    if not proxies:
        raise ValueError("empty proxy list")
    _pool = Pool(proxies, mode)
    socket.socket.connect = _patched_connect
    socket.socket.connect_ex = _patched_connect_ex
    _hook_asyncio()


def deactivate():
    global _pool
    _pool = None
    socket.socket.connect = _orig_connect
    socket.socket.connect_ex = _orig_connect_ex


def autostart():
    """Called from the .pth file in every Python process."""
    if os.environ.get("PYPROXY_DISABLE") == "1":
        return
    path = os.environ.get("PYPROXY_LIST") or CONFIG
    if not os.path.isfile(path):
        return
    try:
        proxies = load_proxies(path)
    except Exception:
        return
    if proxies:
        activate(proxies, os.environ.get("PYPROXY_MODE", "rotate"))


# --------------------------------------------------------------------- CLI

def _site_dirs():
    """Directories whose .pth files Python processes at startup, best first."""
    import site
    dirs = [d for d in site.getsitepackages() if d.rstrip("\\/").endswith("site-packages")]
    if site.ENABLE_USER_SITE:
        dirs.append(site.getusersitepackages())
    return dirs


def _find_installed():
    return [d for d in _site_dirs() if os.path.isfile(os.path.join(d, PTH_NAME))]


def cmd_install(list_path):
    proxies = load_proxies(list_path)
    if not proxies:
        sys.exit("no valid proxies found in " + list_path)
    with open(os.path.abspath(__file__), encoding="utf-8") as f:
        source = f.read()

    installed_to = None
    for d in _site_dirs():
        try:
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "pyproxy.py"), "w", encoding="utf-8") as f:
                f.write(source)
            with open(os.path.join(d, PTH_NAME), "w", encoding="utf-8") as f:
                f.write("import pyproxy; pyproxy.autostart()\n")
            installed_to = d
            break
        except PermissionError:
            continue
    if installed_to is None:
        sys.exit("no writable site-packages found; try an admin prompt")

    os.makedirs(HOME, exist_ok=True)
    with open(list_path, encoding="utf-8") as src, open(CONFIG, "w", encoding="utf-8") as dst:
        dst.write(src.read())
    print(f"Installed {len(proxies)} proxies. All new Python processes now use them.")
    print(f"Site dir: {installed_to}\nBypass for one run: set PYPROXY_DISABLE=1")


def cmd_uninstall():
    removed = False
    for d in _site_dirs():
        for name in (PTH_NAME, "pyproxy.py"):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                os.remove(p)
                removed = True
    print("Uninstalled." if removed else "Nothing to uninstall.")


def cmd_status():
    dirs = _find_installed()
    if not dirs:
        print("Not installed.")
        return
    print(f"Installed in: {', '.join(dirs)}")
    if os.path.isfile(CONFIG):
        print(f"Config: {CONFIG} ({len(load_proxies(CONFIG))} proxies)")
    else:
        print(f"Config missing: {CONFIG} (proxying is inactive)")
    if os.environ.get("PYPROXY_DISABLE") == "1":
        print("PYPROXY_DISABLE=1 is set in this shell.")


def cmd_test(path):
    import urllib.request
    path = path or os.environ.get("PYPROXY_LIST") or CONFIG
    if not os.path.isfile(path):
        sys.exit(f"proxy list not found: {path}")
    proxies = load_proxies(path)
    if not proxies:
        sys.exit(f"no valid proxies in {path}")
    # Ignore HTTP(S)_PROXY env vars so urllib connects through our patch only.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for p in proxies:
        activate([p])
        t = time.time()
        try:
            ip = opener.open("https://api.ipify.org", timeout=15).read().decode()
            print(f"OK   {p!r} -> {ip} ({time.time() - t:.1f}s)")
        except Exception as e:
            print(f"FAIL {p!r}: {e}")
    deactivate()


def cmd_run(script, args):
    import runpy
    path = os.environ.get("PYPROXY_LIST") or CONFIG
    if not os.path.isfile(path):
        sys.exit("set PYPROXY_LIST or run 'install' first")
    proxies = load_proxies(path)
    if not proxies:
        sys.exit(f"no valid proxies in {path}")
    activate(proxies, os.environ.get("PYPROXY_MODE", "rotate"))
    sys.argv = [script] + args
    runpy.run_path(script, run_name="__main__")


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
    elif a[0] == "install" and len(a) == 2:
        cmd_install(a[1])
    elif a[0] == "uninstall":
        cmd_uninstall()
    elif a[0] == "status":
        cmd_status()
    elif a[0] == "test":
        cmd_test(a[1] if len(a) > 1 else None)
    elif a[0] == "run" and len(a) >= 2:
        cmd_run(a[1], a[2:])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
