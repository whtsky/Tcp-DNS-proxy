#! /usr/bin/python
# -*- coding: utf-8 -*-
# cody by zhouzhenster@gmail.com

#
# Change log:
#
# 2011-10-23  use SocketServer to run a multithread udp server
# 2012-04-16  add more public dns servers support tcp dns query
# 2013-05-14  merge code from linkerlin, add gevent support
# 2013-06-24  add lru cache support
# 2013-08-14  add option to disable cache
# 2014-01-04  add option "servers", "timeout" @jinxingxing

#  8.8.8.8        google
#  8.8.4.4        google
#  156.154.70.1   Dnsadvantage
#  156.154.71.1   Dnsadvantage
#  208.67.222.222 OpenDNS
#  208.67.220.220 OpenDNS
#  198.153.192.1  Norton
#  198.153.194.1  Norton

try:
    from gevent import monkey
    monkey.patch_all()
except ImportError:
    print "*** Install gevent to have better performance."

import os
import socket
import struct
import threading
import SocketServer
import optparse

from pylru import lrucache

DHOSTS = [
    '8.8.8.8', '8.8.4.4', '156.154.70.1', '156.154.71.1',
    '208.67.222.222', '208.67.220.220', '74.207.247.4', '209.244.0.3',
    '8.26.56.26'
]

DPORT = 53
TIMEOUT = 20
CACHE = None


def hexdump(src, width=16):
    """ hexdump, default width 16
    """
    FILTER = ''.join(
        [(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    result = []
    for i in xrange(0, len(src), width):
        s = src[i:i + width]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%04X   %s   %s\n" % (i, hexa, printable))
    return ''.join(result)


def bytetodomain(s):
    """bytetodomain

    03www06google02cn00 => www.google.cn
    """
    domain = []
    i = 0
    length = struct.unpack('!B', s[0:1])[0]

    while length:
        i += 1
        domain += s[i:i + length]
        i += length
        length = struct.unpack('!B', s[i:i + 1])[0]
        if length:
            domain.append('.')

    return "".join(domain)


def QueryDNS(server, port, querydata):
    """tcp dns request

    Args:
        server: remote tcp dns server
        port: remote tcp dns port
        querydata: udp dns request packet data

    Returns:
        tcp dns response data
    """
    # length
    Buflen = struct.pack('!h', len(querydata))
    sendbuf = Buflen + querydata
    data = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set socket timeout
        s.settimeout(TIMEOUT)
        s.connect((server, int(port)))
        s.send(sendbuf)
        data = s.recv(2048)
    except Exception, e:
        print '[ERROR] QueryDNS: %s' % e.message
    finally:
        if s:
            s.close()
        return data


def transfer(querydata, addr, server):
    """send udp dns respones back to client program

    Args:
        querydata: udp dns request data
        addr: udp dns client address
        server: udp dns server socket

    Returns:
        None
    """

    if not querydata:
        return

    domain = bytetodomain(querydata[12:-4])
    qtype = struct.unpack('!h', querydata[-4:-2])[0]

    print 'domain:%s, qtype:%x, thread:%d' % \
        (domain, qtype, threading.activeCount())

    response = None
    t_id = querydata[:2]
    key = querydata[2:].encode('hex')

    if CACHE and key in CACHE:
        response = CACHE[key]
        server.sendto(t_id + response[4:], addr)
        return

    for ip, port in DHOSTS:
        response = QueryDNS(ip, port, querydata)
        if CACHE:
            CACHE[key] = response

        # udp dns packet no length
        server.sendto(response[2:], addr)
        return

    if response is None:
        print "[ERROR] Tried many times and failed to resolve %s" % domain


class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass


class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    # much faster rebinding
    allow_reuse_address = True

    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        addr = self.client_address
        transfer(data, addr, socket)


def main():
    global TIMEOUT, DHOSTS, CACHE

    parser = optparse.OptionParser()
    parser.add_option("-c", "--cached", action="store_true",
                      dest="cache", default=False, help="Enable LRU cache")
    parser.add_option("-s", "--servers", action="store", dest="dns_servers",
                      help="Specifies the DNS server, separated by ','."
                      "default port is 53 (eg. 8.8.8.8, 8.8.4.4:53)")
    parser.add_option("-t", "--timeout", action="store",
                      dest="query_timeout", help="DNS query timeout")
    parser.add_option("-l", "--local", action="store_true",
                      dest="local", default=True,
                      help="Only accept local connections")
    options, _ = parser.parse_args()

    if options.query_timeout:
        TIMEOUT = float(options.query_timeout)
    if options.dns_servers:
        DHOSTS = [x.strip() for x in options.dns_servers.split(',')]
    if options.cache:
        CACHE = lrucache(100)
    if options.local:
        listen_ip = "127.0.0.1"
    else:
        listen_ip = "0.0.0.0"

    if os.name == 'nt':
        os.system('title tcpdnsproxy')

    print '>> TCP DNS Proxy, https://github.com/henices/Tcp-DNS-proxy'
    print '>> DNS Servers:\n%s' % ('\n'.join(DHOSTS))
    print '>> Query Timeout: %f' % TIMEOUT
    print '>> Enable Cache: %r' % options.cache
    print '>> Listen on: %s:53' % listen_ip


    _HOST = []
    for host in DHOSTS:
        if ":" in host:
            ip, port = host.split(':')
        else:
            ip, port = host, DPORT
        _HOST.append((ip, port))
    DHOSTS = _HOST

    print '>> Please wait program init....'
    server = ThreadedUDPServer((listen_ip, 53), ThreadedUDPRequestHandler)
    print '>> Init finished!'
    print '>> Now you can set dns server to 127.0.0.1'

    server.serve_forever()
    server.shutdown()

if __name__ == "__main__":
    main()
