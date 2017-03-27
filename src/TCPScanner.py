import optparse
from socket import *


def connscan(tgt_host, tgt_port):
    """Attempt to create a connection to the target host and port."""
    try:
        connsckt = socket(AF_INET, SOCK_STREAM)
        connsckt.connect((tgt_host, tgt_port))
        print('[+]%d/tcp open' % tgt_port)
        connsckt.close()
    except:
        print('[-]%d/tcp closed' % tgt_port)


def portscan(tgt_host, tgt_ports):
    """Attempt to resolve an IP Address to a friendly hostname, then print hostname or IP address."""
    try:
        tgtIP = gethostbyname(tgt_host)
    except:
        print("[-] Cannot resolve '%s': Unknown host" % tgt_host)
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan Results for: ' + tgtName[0])
    except:
        print('\n[+] Scan Results for: ' + tgtIP)
    setdefaulttimeout(1)
    for tgt_port in tgt_ports:
        print('Scanning port ' + tgt_port)
        connscan(tgt_host, int(tgt_port))

parser = optparse.OptionParser(
    'usage %prog -H' + '<target host> -p <target port>')
parser.add_option('-H', dest='tgt_host', type='string',
                  help='specify target host')
parser.add_option('-p', dest='tgt_port', type='int',
                  help='specify target port')
(options, args) = parser.parse_args()
tgt_host = options.tgt_host
tgt_port = options.tgt_port
if (tgt_host is None) or (tgt_port is None):
    print(parser.usage)
    exit(0)
