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
from logger import logger, enable_pretty_logging

DNS_HOSTS = """
8.8.8.8, 8.8.4.4, 156.154.70.1, 156.154.71.1, 208.67.222.222,
208.67.220.220, 74.207.247.4, 209.244.0.3, 8.26.56.26
"""

TIMEOUT = 20


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
        logger.error(e.message)
    finally:
        if s:
            s.close()
        return data


def cache(key=lambda *args: args[0]):
    def cache_func(f):
        func_name = f.__name__

        def wraps(self, *args, **kwargs):
            cache_key = key(*args)
            server = self.server
            if server.cache_size:
                cache = server.caches.setdefault(
                    func_name,
                    lrucache(server.cache_size)
                )
                if key in cache:
                    return cache[key]
            else:
                cache = None
            result = f(self, *args, **kwargs)
            if cache is not None:
                cache[cache_key] = result
            return result
        return wraps
    return cache_func


class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    # much faster rebinding
    allow_reuse_address = True

    def handle(self):
        """send udp dns respones back to client program

        Returns:
            None
        """

        querydata = self.request[0]
        server = self.request[1]
        addr = self.client_address

        if not querydata:
            return

        domain = self.bytetodomain(querydata[12:-4])
        qtype = struct.unpack('!h', querydata[-4:-2])[0]

        logger.debug('domain:%s, qtype:%x, thread:%d' % \
            (domain, qtype, threading.activeCount()))

        response = self.query(querydata)
        server.sendto(response[2:], addr)

        if response is None:
            logger.warning("Failed to resolve {domain}".format(domain=domain))

    @cache()
    def bytetodomain(self, s):
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

    @cache(key=lambda data: data[2:].encode('hex'))
    def query(self, querydata):
        for ip, port in self.server.hosts:
            response = QueryDNS(ip, port, querydata)
            if response:
                return response


class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, server_address,
                 hosts, timeout, cache_size):
        SocketServer.UDPServer.__init__(
            self,
            server_address=server_address,
            RequestHandlerClass=ThreadedUDPRequestHandler
        )
        _hosts = []
        for host in hosts:
            if ":" in host:
                ip, port = host.split(':')
            else:
                ip, port = host, 53
            _hosts.append((ip, port))
        self.hosts = _hosts
        self.timeout = timeout
        self.cache_size = cache_size
        self.caches = {}


def main():
    enable_pretty_logging()

    parser = optparse.OptionParser()
    parser.add_option("-c", "--cache_size", action="store",
                      dest="cache_size", default=0,
                      help="Size of cache. Set to 0 to disable cache.")
    parser.add_option("-s", "--servers", action="store",
                      dest="dns_servers", default=DNS_HOSTS,
                      help="Specifies the DNS server, separated by ','."
                      "default port is 53 (eg. 8.8.8.8, 8.8.4.4:53)")
    parser.add_option("-t", "--timeout", action="store",
                      dest="query_timeout", default=TIMEOUT,
                      help="DNS query timeout")
    parser.add_option("-l", "--listen", action="store",
                      dest="listen", default="127.0.0.1",
                      help="Listen to which ip address")
    parser.add_option("-d", "--daemon", action="store_true",
                      dest="daemon", default=True,
                      help="Run in daemon")
    options, _ = parser.parse_args()

    if os.name == 'nt':
        os.system('title tcpdnsproxy')

    server = ThreadedUDPServer(
        (options.listen, 53),
        hosts=[x.strip() for x in options.dns_servers.split(',')],
        timeout=options.query_timeout,
        cache_size=int(options.cache_size)
    )
    logger.info("Start listening on {ip}:53".format(ip=options.listen))

    if options.daemon:
        import daemon
        with daemon.DaemonContext():
            server.serve_forever()
    else:
        server.serve_forever()

if __name__ == "__main__":
    main()
