#!/usr/bin/env python3
"""Servidor de teste para o CASDE State Tracker.

Serve URLs com conteúdo controlado para demonstrar o diffing:
  /            -> pagina principal (v1)
  /api/status  -> JSON de status
  /js/app.js   -> bundle JS (v1)
Rodar: python3 test_server.py
Mudar o conteúdo entre execuções: editar as constantes V1/V2 ou usar ?v=2.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler

VERSION = "v2"

PAGES = {
    "/": {
        "content": f"<!DOCTYPE html><html><head><title>CASDE Test</title></head>"
                   f"<body><h1>página principal</h1><p>versão {VERSION}</p>"
                   f"<script src=\"/js/app.js\"></script></body></html>",
        "ctype": "text/html",
    },
    "/api/status": {
        "content": f'{{"status":"ok","version":"{VERSION}","uptime":1234,"feature":"new_auth"}}',
        "ctype": "application/json",
    },
    "/js/app.js": {
        "content": f'// CASDE test bundle {VERSION}\n'
                   f'fetch("/api/status").then(r => r.json()).then(console.log);\n'
                   f'fetch("/api/v2/health").then(r => r.text()).then(console.log);\n',
        "ctype": "application/javascript",
    },
    "/admin": {
        "content": b"<html><body><h1>admin panel</h1><form><input name=user></form></body></html>",
        "ctype": "text/html",
    },
}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = None
        for path, cfg in PAGES.items():
            if self.path == path or self.path.startswith(path + "?"):
                content = cfg["content"]
                body = content if isinstance(content, bytes) else content.encode()
                self.send_response(200)
                self.send_header("Content-Type", cfg["ctype"])
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("[test_server] rodando em :18080 (edite PAGES para simular mudanças)")
    HTTPServer(("127.0.0.1", 18080), H).serve_forever()
