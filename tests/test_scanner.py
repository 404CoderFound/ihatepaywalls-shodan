import socket,threading
from worker.scanners.tcp import scan_endpoint

def test_actual_local_tcp_http_detection():
    server=socket.socket();server.bind(("127.0.0.1",0));server.listen(1);port=server.getsockname()[1]
    def serve():
        conn,_=server.accept();conn.recv(2048);conn.sendall(b"HTTP/1.0 200 OK\r\nServer: LocalFixture/1.0\r\n\r\n");conn.close();server.close()
    thread=threading.Thread(target=serve);thread.start()
    # Use a temporary classification port by extending the known local-test set.
    import worker.scanners.tcp as scanner
    scanner.HTTP_PORTS.add(port)
    result=scan_endpoint("127.0.0.1",port,1,1);thread.join(2)
    assert result and result["service"]=="http" and result["http"]["server"]=="LocalFixture/1.0"
