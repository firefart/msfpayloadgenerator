# msfpayloadgenerator
Generates some metasploit payloads for testing

- Normal exes
- UPX packed
- Python compiled to exes (also UPX packed)
- Powershell stuff
- Java Payloads (execute with java -jar payload.jar)
- Some raw payloads to be executed on a command shell

To install on 64bit Ubuntu/Debian:
```
dpkg --add-architecture i386
apt-get update
apt-get install wine32
apt-get install winbind
```

On Kali:
```
apt-get install python3-netifaces python3-requests
```
Or:
```
pip install netifaces requests
```
