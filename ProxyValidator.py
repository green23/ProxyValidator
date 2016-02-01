import argparse
import socket
import requests
import random
from Queue import Queue
from os import name
from threadpool import ThreadPool, makeRequests


class color:
    def __init__(self):
        if name == "nt":
            # Windows
            self.RED = 0x04
            self.GREY = 0x08
            self.BLUE = 0x01
            self.CYAN = 0x03
            self.BLACK = 0x0
            self.GREEN = 0x02
            self.WHITE = 0x07
            self.PURPLE = 0x05
            self.YELLOW = 0x06
            from ctypes import windll
            def s(c, h=windll.kernel32.GetStdHandle(-11)):
                return windll.kernel32.SetConsoleTextAttribute(h, c)

            def p(m, c=self.BLACK, e=True):
                s(c | c | c)
                if e:
                    print m
                else:
                    print m,
                s(self.RED | self.GREEN | self.BLUE)
        else:
            # Other system(unix)
            self.RED = '\033[31m'
            self.GREY = '\033[38m'
            self.BLUE = '\033[34m'
            self.CYAN = '\033[36m'
            self.BLACK = '\033[0m'
            self.GREEN = '\033[32m'
            self.WHITE = '\033[37m'
            self.PURPLE = '\033[35m'
            self.YELLOW = '\033[33m'

            def p(m, c=self.BLACK, e=True):
                if e:
                    print "%s%s%s" % (c, m, self.BLACK)
                else:
                    print "%s%s%s" % (c, m, self.BLACK),
        self.p = p


class pycui:
    def __init__(self):
        self.c = color()

    def warning(self, m):
        self.c.p("[-] %s" % m, self.c.PURPLE)

    def info(self, m):
        self.c.p("[i] %s" % m, self.c.YELLOW)

    def error(self, m):
        self.c.p("[!] %s" % m, self.c.RED)

    def success(self, m):
        self.c.p("[*] %s" % m, self.c.GREEN)

    # short-func
    def w(self, m):
        self.warning(m)

    def i(self, m):
        self.info(m)

    def e(self, m):
        self.error(m)

    def s(self, m):
        self.success(m)


class genips:

    def i2n(self, i):
        ''' ip to number '''
        ip = [int(x) for x in i.split('.')]
        return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3]

    def n2i(self, n):
        ''' number to ip '''
        return '%s.%s.%s.%s' % (
            (n & 0xff000000) >> 24,
            (n & 0x00ff0000) >> 16,
            (n & 0x0000ff00) >> 8,
            n & 0x000000ff
        )

    def gen(self, start, end):
        ''' genIPS:s=startIP(192.168.1.1);e=endIP(192.168.1.255) '''
        return [self.n2i(n) for n in range(self.i2n(start), self.i2n(end) + 1) if n & 0xff]


class Validator:

    def __init__(self):
        self.args = vars(self.get_args())
        self.cor = color()
        self.cui = pycui()
        self.gen = genips()
        self.result = []

    def banner(self):
        return """
            ____                       _    __      ___     __      __
   / __ \_________  _  ____  _| |  / /___ _/ (_)___/ /___ _/ /_____  _____
  / /_/ / ___/ __ \| |/_/ / / / | / / __ `/ / / __  / __ `/ __/ __ \/ ___/
 / ____/ /  / /_/ />  </ /_/ /| |/ / /_/ / / / /_/ / /_/ / /_/ /_/ / /
/_/   /_/   \____/_/|_|\__, / |___/\__,_/_/_/\__,_/\__,_/\__/\____/_/
                      /____/
        """
    def usage(self):
        self.cor.p(self.banner(), self.cor.RED)
        self.cor.p('PV 1.0 (Proxy Validator)', self.cor.GREEN)
        self.cor.p('\tAuthor: juhongxiaoshou', self.cor.YELLOW)
        self.cor.p('\tModify: 2014/11/27', self.cor.YELLOW)
        self.cor.p('\tGitHub: https://github.com/h01/ProxyValidator', self.cor.YELLOW)
        self.cor.p('\tVersion: 1.0', self.cor.RED)
        self.cor.p('Usage: python ProxyValidator.py [args] [value]', self.cor.GREEN)
        self.cor.p('Args: ', self.cor.PURPLE)
        self.cor.p('\t-v --version\t\tPV version')
        self.cor.p('\t-h --help\t\tHelp menu')
        self.cor.p('\t-i --ip\t\t\tIP: 192.168.1.1-192.168.1.100 or 192.168.1.1')
        self.cor.p('\t-p --port\t\tProxy port (default:8080)')
        self.cor.p('\t-t --thread\t\tScan thread (default:10)')
        self.cor.p('\t-o --out\t\tSave scan result')


    def version(self):
        self.cui.i('ProxyScanner version 1.0')
        exit(0)

    def get_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--ip", help="give ip address, such as 192.168.0.1-1921.68.0.20",
                            type=str, dest='ip')
        parser.add_argument("-p", '--port', help="specify a port", dest='port', type=int)
        parser.add_argument("-t", "--thread", help="specify number of threads", dest="thread", type=int)
        parser.add_argument("-v", "--version", help="version of ProxyValidator", dest="version")
        parser.add_argument("-o", "--out", help="file path of save", dest='out')
        args = parser.parse_args()
        return args

    def parse_ip(self):
        if self.args['ip']:
            self.args['ip'] = self.args['ip'].split('-')
            if len(self.args['ip']) == 2:
                if self.args['ip'][0] > self.args['ip'][1]:
                    print "ip range error"
                    self.args['ip'] = ""
                else:
                    ip = self.gen.gen(self.args['ip'][0], self.args['ip'][1])
                    return ip

    def validate_port(self, host, port):
        try:
            _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _s.settimeout(3)
            _s.connect((host, port))
            _s.close()
            return True
        except Exception as err:
            print err
            return False

    def validate_host(self, host, port):
        session = requests.session()
        session.proxies = {
            "http": "http://%s:%d" % (host, port),
            # "https": "http://%s:%d" % (host, port),
        }
        print session.proxies
        user_agent = [
            'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
            'Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36',
        ]
        session.headers = {
            "scheme": "https",
            "user-agent": user_agent[random.randint(0, 4)],
        }
        respons = session.get('https://api.douban.com/v2/user/1000001')
        if respons.status_code == 200:
            return True
            print respons.content
        else:
            print respons.status_code
            return False

    def run(self, args):
        if not args['ip'] or not args['port'] or not args['thread']:
            self.usage()
            return False

        if self.validate_port(args['ip'], args['port']):
            self.cui.s('Open: %s' % args['ip'])
        else:
            self.cui.e('Close: %s' % args['ip'])
            return False
        if self.validate_host(args['ip'], args['port']):
            self.cui.s('OK: %s:%s' % (args['ip'], args['port']))
            self.result.append('%s:%s' % (args['ip'], args['port']))
        else:
            self.cui.i('No: %s:%s' % (args['ip'], args['port']))
            return False

    def result(self):
        if len(self.result) > 0:
            self.cui.i('Scan result:')
            for r in self.result:
                print r
            # if self._s != '':
            #     _f = open(self._s, 'a')
            #     for _r in self._r:
            #         _f.write('%s:%s\n' % (_r, self._p))
            #     _f.close()
            #     self.cui.s('Save as (%s)' % self._s)
        else:
            self.cui.i('Not result!')

    def start_thread(self):
        args_list = []
        ips = self.parse_ip()
        for ip in ips:
            args = self.args.copy()
            args['ip'] = ip
            args_list.append(args)
        self.cui.w('Proxy Scanner started')
        self.cui.i('Nums: %s' % len(args_list))
        self.cui.i('Port: %s' % self.args['port'])
        self.cui.i('Thread: %s' % self.args['thread'])
        pool = ThreadPool(self.args['thread'])
        reqs = makeRequests(self.run, args_list)
        [pool.putRequest(req) for req in reqs]
        pool.wait()




Validator().start_thread()
