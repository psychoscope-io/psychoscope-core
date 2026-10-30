#!/usr/bin/env python3
"""Servidor HTTP de teste que imita as releases do GitHub (inclusive o redirect de /releases/latest).

  release_server.py RAIZ ARQUIVO_DA_PORTA [ENDERECO]

Serve RAIZ/<repositorio>/releases/download/vX.Y.Z/... e responde a /<repositorio>/releases/latest com
um redirect para a maior versao. Grava a porta (escolhida pelo sistema) em ARQUIVO_DA_PORTA. Usado por
test_get.sh (so em 127.0.0.1) e test_distros.sh (no gateway do Docker). Nao e instalado nem publicado.
"""
import functools, http.server, os, re, sys
root, portfile = sys.argv[1], sys.argv[2]
bind = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _route(self, fallback):
        m = re.fullmatch(r"/([\w.-]+)/releases/latest", self.path)
        if m:
            d = os.path.join(root, m.group(1), "releases", "download")
            vers = sorted(os.listdir(d), key=lambda v: tuple(map(int, v[1:].split(".")))) if os.path.isdir(d) else []
            self.send_response(302)
            self.send_header("Location", "/%s/releases/%s" % (m.group(1), "tag/" + vers[-1] if vers else ""))
            self.end_headers()
        elif re.fullmatch(r"/[\w.-]+/releases(/tag/v[\d.]+)?", self.path):
            self.send_response(200)
            self.end_headers()
        else:
            fallback()

    def do_GET(self):
        self._route(super().do_GET)

    def do_HEAD(self):
        self._route(super().do_HEAD)

srv = http.server.ThreadingHTTPServer((bind, 0), functools.partial(Handler, directory=root))
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
