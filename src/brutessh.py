import pexpect
PROMPT = ['# ', '>>> ', '> ', '\$ ']


def send_command(child, cmd):
    """A function to send commands during ssh interaction."""
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)


def connect(user, host, password):
    """Connect and send username/password."""
    ssh_newkey = 'Are you sure you want to continue connecting'
    conn_str = 'ssh ' + user + '@' + host
    child = pexpect.spawn(conn_str)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, 
                       '[P|p]assword:'])
    if ret == 0:
        print('[-] Error Connecting')
        return
    if ret == 1:
        child.sendline('yes')
    ret = child.expect([pexpect.TIMEOUT, '[P|p]assword:'])
    if ret == 0:
        print('[-] Error Connecting')
        return
    child.sendline(password)
    child.expect(PROMPT)
    return child

def main():
    """Run the function."""
    host = 'localhost'
    user = 'root'
    password = 'toor'
    child = connect(user, host, password)
    send_command(child, 'cat /etc/shadow | grep root')

if __name__ == '__main__':
    main()