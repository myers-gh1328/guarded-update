#!/usr/bin/env python3
"""Disposable loopback-only TLS test server; never accepts real credentials."""
import http.server
import os
import pathlib
import ssl
import subprocess
import sys

root=pathlib.Path(sys.argv[1]);san=sys.argv[2]
assert root.is_absolute() and root.is_dir() and san in ('ip','wrong')
os.umask(0o077)
def command(*args):
    subprocess.run(['/usr/bin/openssl',*args],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=15)
def cert(name,entry):
    config=root/(name+'.cnf');config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=synthetic-test\n[ext]\nbasicConstraints=critical,CA:TRUE\nsubjectAltName='+entry+'\n')
    command('req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.pem')),'-days','1','-config',str(config))
cert('server','IP:127.0.0.1' if san=='ip' else 'DNS:localhost')
cert('other','IP:127.0.0.1')
command('ecparam','-name','prime256v1','-genkey','-noout','-out',str(root/'device.key'))
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        length=int(self.headers.get('content-length','0'))
        if not 0<=length<=65536:self.send_error(413);return
        self.rfile.read(length)
        if self.path.endswith('/reports'):
            self.send_response(302);self.send_header('Location','https://example.invalid/');self.end_headers();return
        payload=b'{"schema_version":1}'
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key');context.set_ecdh_curve('prime256v1')
server.socket=context.wrap_socket(server.socket,server_side=True)
(root/'port').write_text(str(server.server_port))
server.serve_forever()
