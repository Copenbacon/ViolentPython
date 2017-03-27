"""A port scanning script from the Violent Python cookbook."""
import optparse
from socket import *
from threading import *

screen_lock = Semaphore(value=1)


def connscan(tgt_host, tgt_port):
    """Attempt to create a connection to the target host and port."""
    try:
        connsckt = socket(AF_INET, SOCK_STREAM)
        connsckt.connect((tgt_host, tgt_port))
        connsckt.send('ViolentPython\r\n')
        results = connsckt.recv(100)
        screen_lock.acquire()
        print('[+]%d/tcp open' % tgt_port)
        print('[+] ' + str(results))
    except:
        screen_lock.acquire()
        print('[-]%d/tcp closed' % tgt_port)
    finally:
        screen_lock.release()
        connsckt.close()


def portscan(tgt_host, tgt_ports):
    """Attempt to resolve an IP Address to a friendly hostname, then print hostname or IP address."""
    try:
        tgt_ip = gethostbyname(tgt_host)
    except:
        print("[-] Cannot resolve '%s': Unknown host" % tgt_host)
        return
    try:
        tgt_name = gethostbyaddr(tgt_ip)
        print('\n[+] Scan Results for: ' + tgt_name[0])
    except:
        print('\n[+] Scan Results for: ' + tgt_ip)
    setdefaulttimeout(1)
    for tgt_port in tgt_ports:
        t = Thread(target=connscan, args=(tgt_host, int(tgt_port)))
        t.start()


def main():
    """Parse -p and -H flags and scan the ip and port associated with it."""
    parser = optparse.OptionParser(
        'usage %prog -H' + '<target host> -p <target port>')
    parser.add_option('-H', dest='tgt_host', type='string',
                      help='specify target host')
    parser.add_option('-p', dest='tgt_port', type='string',
                      help='specify target port')
    (options, args) = parser.parse_args()
    tgt_host = options.tgt_host
    tgt_ports = str(options.tgt_port).split(', ')
    if (tgt_host is None) or (tgt_ports[0] is None):
        print(parser.usage)
        exit(0)
    portscan(tgt_host, tgt_ports)

if __name__ == '__main__':
    main()