import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

if sys.platform == "win32" and sys.version_info < (3, 14):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# ---------------------------------------------------------------------------
# Fake file content served over HTTP
# ---------------------------------------------------------------------------

FAKE_CONTENT: dict[str, tuple[str, bytes]] = {
    "/.env": (
        "text/plain",
        b"""DB_HOST=localhost
DB_PORT=5432
DB_NAME=production_db
DB_USER=postgres
DB_PASSWORD=Sup3rS3cr3tP@ssw0rd!

SECRET_KEY=django-insecure-abc123xyz789supersecretkeydonotuseInProduction
API_KEY=sk-prod-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
STRIPE_SECRET_KEY=DEMO_NOT_A_REAL_STRIPE_KEY_REPLACE_ME_XXXXXXXXX
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DEBUG=True
ALLOWED_HOSTS=*
""",
    ),
    "/.env.local": (
        "text/plain",
        b"""NEXT_PUBLIC_API_URL=http://localhost:8000
DATABASE_URL=postgres://dev:devpassword123@localhost:5432/myapp_local
NEXTAUTH_SECRET=localsecret_abc123
""",
    ),
    "/.env.production": (
        "text/plain",
        b"""DATABASE_URL=postgres://produser:ProdP@ssw0rd_2024@db.internal:5432/myapp_prod
REDIS_URL=redis://:redisP@ss123@cache.internal:6379
SENTRY_DSN=https://examplePublicKey@o0.ingest.sentry.io/0
""",
    ),
    "/.git/config": (
        "text/plain",
        b"""[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/acme-corp/production-app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = deploy-bot
\temail = deploy@acme-corp.com
""",
    ),
    "/wp-config.php": (
        "text/plain",
        b"""<?php
define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'WpAdm1nP@ss2024!');
define('DB_HOST', 'localhost');
define('AUTH_KEY',        'x7#kL!mN9$pQ2rS5tU8vW1yZ3aB6cD0eF4gH7iJ');
define('SECURE_AUTH_KEY', 'y8$lM!nO0%qR3sT6uV9wX2zA4bC7dE1fG5hI8jK');
define('LOGGED_IN_KEY',   'z9%mN!oP1&rS4tU7vW0xY3aZ5bC8dE2fG6hI9jL');
define('NONCE_KEY',       'a0&nO!pQ2\'sT5uV8wX1yZ4aC7bD0eF3gH7iJ0kM');
$table_prefix = 'wp_';
define('WP_DEBUG', false);
""",
    ),
    "/.htpasswd": (
        "text/plain",
        b"""admin:$apr1$xyz12345$FakeHashedPasswordForDemoOnly00
developer:$apr1$abc98765$AnotherFakeHashedPasswordHere00
""",
    ),
    "/backup.sql": (
        "text/plain",
        b"""-- MySQL dump 10.13  Distrib 8.0.32
-- Host: localhost    Database: production_db
--
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `users` VALUES (1,'admin','admin@acme.com','$2b$12$FakeHashedPassword123456789012345678901234');
INSERT INTO `users` VALUES (2,'john.doe','john@acme.com','$2b$12$AnotherFakeHashedPassword09876543210987');
CREATE TABLE `api_keys` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `key_hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `api_keys` VALUES (1,1,'DEMO_NOT_A_REAL_STRIPE_KEY_REPLACE_ME_XXXXXXXXX');
""",
    ),
    "/config/database.yml": (
        "text/plain",
        b"""default: &default
  adapter: postgresql
  encoding: unicode
  pool: 5

development:
  <<: *default
  database: myapp_development
  username: postgres
  password:

test:
  <<: *default
  database: myapp_test
  username: postgres
  password:

production:
  <<: *default
  database: myapp_production
  username: myapp_prod
  password: ProdDBP@ssw0rd_2024!
  host: db.internal.acme.com
""",
    ),
    "/.DS_Store": (
        "application/octet-stream",
        b"\x00\x00\x00\x01Bud1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ),
    "/admin": (
        "text/html",
        b"""<!DOCTYPE html><html><head><title>Admin Panel</title></head>
<body><h1>Admin Panel</h1><p>Welcome to the administration area.</p>
<form><input name="user" placeholder="Username"><input type="password" name="pass" placeholder="Password">
<button>Login</button></form></body></html>""",
    ),
    "/wp-admin": (
        "text/html",
        b"""<!DOCTYPE html><html><head><title>WordPress Admin</title></head>
<body><h1>WordPress Administration</h1><p>Howdy! Please log in.</p></body></html>""",
    ),
    "/wp-login.php": (
        "text/html",
        b"""<!DOCTYPE html><html><head><title>WordPress Login</title></head>
<body><h1>WordPress Login</h1>
<form method="post"><p><label>Username<br><input name="log" type="text"></label></p>
<p><label>Password<br><input name="pwd" type="password"></label></p>
<input type="submit" value="Log In"></form></body></html>""",
    ),
    "/phpmyadmin": (
        "text/html",
        b"""<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>
<body><h1>phpMyAdmin</h1><p>Welcome to phpMyAdmin. Please log in.</p>
<form><input name="pma_username" placeholder="Username">
<input type="password" name="pma_password" placeholder="Password">
<button>Go</button></form></body></html>""",
    ),
    "/adminer.php": (
        "text/html",
        b"""<!DOCTYPE html><html><head><title>Adminer 4.8.1</title></head>
<body><h1>Adminer 4.8.1</h1><p>Database management tool.</p>
<form><select name="driver"><option>MySQL</option><option>PostgreSQL</option></select>
<input name="server" value="localhost"><input name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input name="db" placeholder="Database"><button>Login</button></form></body></html>""",
    ),
    "/administrator": (
        "text/html",
        b"""<!DOCTYPE html><html><head><title>Administrator Panel</title></head>
<body><h1>Administrator Panel</h1><p>Restricted area. Authorised users only.</p></body></html>""",
    ),
    "/": (
        "text/html",
        b"""<!DOCTYPE html><html><head><title>Demo Vulnerable Server</title>
<style>body{font-family:monospace;max-width:700px;margin:40px auto;padding:0 20px}
code{background:#f0f0f0;padding:2px 6px;border-radius:3px}
.warn{color:#c00;font-weight:bold}</style></head>
<body>
<h1>Demo Vulnerable Server</h1>
<p>This server intentionally exposes every vulnerability checked by the security scanner.
It is for <strong>local demo and testing only</strong>.</p>
<p>Point your scanner at <code>http://localhost:8080</code></p>
<h2>What is exposed</h2>
<ul>
<li>Secret files: <code>/.env</code>, <code>/.git/config</code>, <code>/backup.sql</code>, and more</li>
<li>Admin panels: <code>/admin</code>, <code>/phpmyadmin</code>, <code>/adminer.php</code>, and more</li>
<li>No HTTPS / no HTTP-to-HTTPS redirect</li>
<li>Open ports: Redis (6379), Docker API (2375), MySQL (3306), PostgreSQL (5432), MongoDB (27017)</li>
</ul>
<p class="warn">NEVER expose this server to the internet.</p>
</body></html>""",
    ),
}

INDEX_HTML = FAKE_CONTENT["/"][1]

# ---------------------------------------------------------------------------
# HTTP server (runs in a daemon thread)
# ---------------------------------------------------------------------------


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        pass  # suppress access logs

    def do_GET(self):
        entry = FAKE_CONTENT.get(self.path)
        if entry is None:
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        content_type, body = entry
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_http_server():
    server = HTTPServer(("", 8080), VulnerableHandler)
    server.serve_forever()


# ---------------------------------------------------------------------------
# TCP mock services (asyncio)
# ---------------------------------------------------------------------------


async def redis_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=2.0)
        if b"PING" in data:
            writer.write(b"+PONG\r\n")
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def docker_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        await asyncio.wait_for(reader.read(4096), timeout=2.0)
        body = b'{"ApiVersion":"1.41","Os":"linux","Arch":"amd64","ServerVersion":"24.0.5"}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        writer.write(response)
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


def make_bare_handler(greeting: bytes):
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            writer.write(greeting)
            await writer.drain()
            await asyncio.sleep(2.0)
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    return handler


async def try_start_server(handler, port: int):
    try:
        server = await asyncio.start_server(handler, "", port)
        return server
    except OSError as e:
        print(f"  WARNING: Could not bind port {port}: {e}")
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main():
    # Start HTTP server in background thread
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()

    # Start TCP mock services
    servers = []
    for server in await asyncio.gather(
        try_start_server(redis_handler, 6379),
        try_start_server(docker_handler, 2375),
        try_start_server(make_bare_handler(b"MySQL Demo\n"), 3306),
        try_start_server(make_bare_handler(b"PostgreSQL Demo\n"), 5432),
        try_start_server(make_bare_handler(b"MongoDB Demo\n"), 27017),
    ):
        if server is not None:
            servers.append(server)

    print("=" * 62)
    print("  DEMO VULNERABLE SERVER — security scanner test target")
    print("=" * 62)
    print("  HTTP server:      http://localhost:8080")
    print("  Redis mock:       localhost:6379  (no auth — CRITICAL)")
    print("  Docker API mock:  localhost:2375  (unauthenticated — CRITICAL)")
    print("  MySQL mock:       localhost:3306  (CRITICAL)")
    print("  PostgreSQL mock:  localhost:5432  (CRITICAL)")
    print("  MongoDB mock:     localhost:27017 (CRITICAL)")
    print()
    print("  NOTE: Ports 22 (SSH), 21 (FTP), 3389 (RDP) require")
    print("        elevated/Administrator privileges and are NOT started.")
    print("        Run as Administrator to test those HIGH findings.")
    print()
    print("  Point your scanner at: http://localhost:8080")
    print("  Press Ctrl+C to stop.")
    print("=" * 62)

    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        for s in servers:
            s.close()
        for s in servers:
            await s.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down demo server.")
