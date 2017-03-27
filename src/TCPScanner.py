import optparse
from socket import *

def connscan(tgtHost, tgtPort):
    try:
        connsckt = socket(AF_INET, SOCK_STREAM)
        connsckt.connect((tgtHost, tgtPort))
        print('[+]%d/tcp open' % tgtPort)
        connsckt.close()
    except:
        print('[-]%d/tcp closed' % tgtPort)

def portscan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve '%s': Unknown host" % tgtHost)
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan Results for: ' + tgtName[0])
    except:
        print('\n[+] Scan Results for: ' + tgtIP)
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        print('Scanning port ' + tgtPort)
        connscan(tgtHost, int(tgtPort))

parser = optparse.OptionParser(
    'usage %prog -H' + '<target host> -p <target port>')
parser.add_option('-H', dest='tgtHost', type='string',
                  help='specify target host')
parser.add_option('-p', dest='tgtPort', type='int',
                  help='specify target port')
(options, args) = parser.parse_args()
tgtHost = options.tgtHost
tgtPort = options.tgtPort
if (tgtHost is None) or (tgtPort is None):
    print(parser.usage)
    exit(0)
