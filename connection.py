# -*- coding: utf-8 -*-

from gevent import socket
from utils import crypt
import struct
import gevent
import sys
import time

def create_connection(address, timeout=None, **ssl_args):
    """客户端创建连接,返回sock
    :自带有一个 from gevent.socket import create_connection, 不过没有ssl参数
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
    
    if timeout:
        sock.settimeout(timeout)
    if ssl_args:
        from gevent.ssl import wrap_socket
        sock = wrap_socket(sock, **ssl_args)
        
    host = address[0]
    port = int(address[1]) 
    sock.connect((host, port))
    
    return sock


class Connection(object):
    reconnect_delay = 8 # 重连等待时间
    
    def __init__(self, address, uid, password):
        self.address = address
        self.uid = uid
        self.password = password
        self.header_fmt = struct.Struct(">I")
        self.jobs = []
        self.crypt_key = None
        self.encrypt = True
        
        self.connect()

    def connect(self):
        if self.jobs: map(lambda g: g.kill, self.jobs)
        self.conn = create_connection(self.address)
        self.jobs.append(gevent.spawn(self.recv_data))
        self.connection_made()
        
    def connection_made(self):
        # 握手准备消息
        data = "\x00\x00"
        self.sendall(data)
        
    def close(self):
        if self.jobs: map(lambda g: g.kill, self.jobs)
        self.conn.close()
        
    def reconnect(self, delay):
        while True:
            self.conn.close()
            try:
                print "Trying reconnect.."
                self.connect()
                print "Reconneced."
                break
            except:
                print sys.exc_info()
            gevent.sleep(delay)
    
    def sendall(self, data):
        if self.encrypt and self.crypt_key:
            data = crypt(data, self.crypt_key)
        length = len(data)
        data = struct.pack(">I%ds"%length, length, data)
        self.conn.sendall(data)
        
    def recv_data(self):
        while True:
            try:
                # FIXME: 改为makefile接口
                length = self.conn.recv(4)
                if not length:
                    self.on_connection_closed()
                    return
                length = self.header_fmt.unpack(length)[0]

                # FIXME: 改为makefile接口
                data = self.conn.recv(length)
            except:
                self.on_connection_lost()
                return
                # break
            
            print "raw recv:", repr(struct.pack(">I", length)+data)
            if self.encrypt and self.crypt_key:
                data = crypt(data, self.crypt_key)
            print "crypt:", repr(data)
            self.on_data(data)
            
    def on_connection_closed(self):
        self.close()
        print "closed."

    def on_connection_lost(self):
        self.close()
        print "lost."

    def on_data(self, data):
#         print "got: %s " % repr(data)
        msgtype, msg = data[0], data[1:]
        print "msgtype, msg, crypt_key:", ord(msgtype), repr(msg), self.crypt_key
        cmd = getattr(self, "cmd_%s"%ord(msgtype), None)
        if cmd: cmd(msg)
        
    def cmd_0(self, msg):
        """握手"""
        subtype, crypt_key = struct.unpack(">BI", msg)
        if subtype == 1 and crypt_key:
            self.sendall("\x00\x02")
            self.crypt_key = crypt_key
        
        self.jobs.append(gevent.spawn(self.req_1))
        self.req_2()
    
    def cmd_2(self, msg):
        """登陆"""
        if msg == "\x00":
            print "logined."
            
        self.req_4(10001, "ooxx")
        
    def cmd_4(self, msg):
        """聊天"""
        print struct.unpack(">IIBQ4B%ds"%(len(msg)-struct.calcsize(">IIBQ4B")), msg)
            
    def req_1(self):
        """心跳"""
        data = "\x01"
        while 1:
            self.sendall(data)
            gevent.sleep(90)
    
    def req_2(self):
        """登陆"""
        data = "\x02" + struct.pack(">I%ds"%len(self.password), self.uid, self.password)
        self.sendall(data)
        
    def req_4(self, to, ctx, flg1=0, flg2=0, flg3=0, flg4=0):
        """聊天"""
        src = self.uid
        line = 1
        st = int(time.time()*1000)
        data = "\x04" + struct.pack(">IIBQBBBB%ds"%len(ctx), to, src, line, st, flg1, flg2, flg3, flg4, ctx)
        self.sendall(data)
        
if __name__ == "__main__":
    c = Connection(("127.0.0.1", 7005), 10001, "112358")
#     c.close()
#     c.reconnect(10)
#     c.sendall('\x00\x00\x00\x05hello')
    
    gevent.wait()