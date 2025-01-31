
# Client-Side Path Traversal (_CSPT_) Mitigation / CSP Extension

Note: the format of this proposal was highly inspired by ["_TC39 proposal for mitigating prototype pollution_"](https://github.com/tc39/proposal-symbol-proto). This proposal does not consider the issue of CSPT in non-browser contexts, however the problem space does include that and other contexts. 

# TOC
* [tl;dr](#tldr)
* [Problem Description](#problem-description)
  * [Double-Dot URL Path Shortening](#double-dot-url-path-shortening)
  * [Non-File Reverse Solidus Path URL Strings](#non-file-reverse-solidus-path-url-strings)
* [Proposed Solutions](#proposed-solutions)
  * [New CSP Expressions](#new-csp-expressions)
    * [`no-shortening` CSP Expression](#no-shortening-csp-expression)
    * [`no-reverse-solidus` CSP Expression](#no-reverse-solidus-csp-expression)
  * [Limitations](#limitations)
    * [Server-Side Path Decoding](#server-side-path-decoding)
* [What Will This Break?](#what-will-this-break)
  * [Languages Without Canonicalization](#languages-without-canonicalization)
* [Appendix](#appendix)
  * [Double Dot Following URLs](#double-dot-following-urls)
  * [Double Dot Encoded Following URLs](#double-dot-encoded-following-urls)
  * [`invalid-reverse-solidus` Following URLs](#invalid-reverse-solidus-following-urls)
  * [`invalid-reverse-solidus` Encoded Following URLs](#invalid-reverse-solidus-encoded-following-urls)

# tl;dr

This proposal seeks to mitigate common security issues that arise from the default-shortening of URL paths by treating [_double-dot URL path segments_](https://url.spec.whatwg.org/#double-dot-path-segment) (`/..`) as navigation to parent paths, as well as treating [_invalid reverse solidus_](https://url.spec.whatwg.org/#invalid-reverse-solidus) (`\`) as valid forward solidus markers (`/`), by extending the Content-Security-Policy (CSP) feature to include new expressions that allow or disallow certain canonicalization techniques: `allow-shortening`, `no-shortening`, `allow-reverse-solidus`, `no-reverse-solidus`. For example, it would be possible to communicate the browser whether `https://example.com/dir1/../dir3/` and `https://example.com\dir1\..\dir3\` should be considered valid URLs, and terminate parsing of such URLs in different contexts. By providing an opt-in feature, webmasters may explicitly state whether they intend to support these canonicalization methods, and protect their users against Client-Side Path Traversal (CSPT) vulnerabilities.


# Problem Description

## Double-Dot URL Path Shortening

Browsers following WHATWG's URL standard parse double-dot URL paths such as `/path1/../path3/` by shortening the path depending on the depth of the path and the amount of `/..` segments. For example, a website which loads an image using the HTML:

```html
<img src="/images/uploads/../static/logo.png" />
```

will entice the browser to load the resource from `/images/static/logo.png`. This initial declaration of `/images/uploads/../static/logo.png` is opaque to the server which serves the image: before the browser sends the request to the server, it first canonicalizes the path as `/images/static/logo.png`.

Although the above example is inconspicuous, the automatic canonicalization can lead to vulnerabilities for users. Take for example the following webpage:

```html
<head>
    <script>
        async function loadArticle() {
            const articleName = new URLSearchParams(window.location.search).get('articleName');
            
            const articleUrl = `https://example.com/static/article/{$articleName}`;
            const response = await fetch(articleUrl);
            const articleHtml = await response.text();
            
            document.getElementById('content').innerHTML = articleHtml;
        }
        
        window.onload = loadArticle;
    </script>
</head>
<body>
    <h1>Article Viewer</h1>
    <div id="content">Loading...</div>
</body>
```
Due to the lack of sanitization in the script and due to the browser's canonicalization, if the `articleName` parameter contains a double-dot, the fetched URL will be critically altered. For example:

| Example # | `articleName` | Request URL |
|-|-|-|
| 1 | `../../dynamic/user-uploads/malicious-file.png` | `https://example.com/dynamic/user-uploads/malicious-file.png` |
| 2 | `..%2F..%2Fdynamic%2Fuser-uploads%2Fmalicious-file.png` | `https://example.com/dynamic/user-uploads/malicious-file.png` |
| 3 | `..` | `https://example.com/static/` |

Note: `png` files have been chosen in the above example to exemplify a website which may allow uploading of users' images. Since the Javascript code sets the response to an `innerHTML`, any textual comments stored in the PNG's EXIF data will be attached to the page (including HTML or Javascript).

In example 1, the `articleName` is simply appended to the URL, resulting in `fetch()` navigating to the canonicalized URL. 

For the above code, a common (albeit incorrect) coding pattern that has been observed is to check whether `window.location.search` contains the `/` character. However, as can be seen in example 2, `URLSearchParams()` parses and decodes parameters, leading to `$articleName` being the same as in example 2:

```js
new URLSearchParams("?articleName=../../").get("articleName") === new URLSearchParams("?articleName=..%2F..%2F").get("articleName")  
  true
```

A method, typically considered secure, of handling the above operation is to encode the path before appending it to the URL. For example:

```js
const articleUrl = `https://example.com/static/article/${encodeURIComponent(articleName)}`;
```

While the above operation securely handles examples 1 and 2, it does not handle example 3, as `encodeURIComponent()` does not encode the dot characters, and a single path can be traversed upwards. 

All three of the above cases indicate that remarkable care must be taken when constructing strings from user input to be requested by the browser. It does not necessitate programming by an inexperienced developer to get this wrong, and is instead indicative of a dangerous design.

This issue is so common that the term "client-side path traversal" (CSPT) has been coined to refer to this class of vulnerability. CSPT has been seeing more and more research as of late. These types of vulnerabilities have been identified in a wide range of websites, with its application being similar to cross-request site forgery (CSRF). These vulnerabilities have been found in web applications which [do not use query parameters](https://netragard.com/saving-csrf-client-side-path-traversal-to-the-rescue/), have been abused to [perform CSS injection](https://hackerone.com/reports/1245165) leading to full-account-takeover, and have been abused to interact with [privileged browser extensions](https://medium.com/@renwa/client-side-path-traversal-cspt-bug-bounty-reports-and-techniques-8ee6cd2e7ca1). Vulnerabilities may arise from stored values instead of queryable parameters on the visited webpage, such as [this 1-client Gitlab takeover](https://gitlab.com/gitlab-org/gitlab/-/issues/365427) vulnerability in 2022. Two different public tools already exist for automatically identifying websites vulnerable to CSPT: [CSPTBurpExtension](https://github.com/doyensec/CSPTBurpExtension) by DoyenSec for Burp Suite, and [Gecko](https://github.com/vitorfhc/gecko), by  Vitor Falcao.

Given that attention to this class of vulnerability has been rising, it now raises the question as to whether browsers should, on standard webpages, be shortening URL paths unless explicitly necessary. The vast majority of websites do not rely on this functionality, and it has proven to be an edgecase that is unsafely handled by developers.

It is expected that the number of vulnerable applications will continue to grow, as well as the detection and exploitation of these types of vulnerabilities, as the issue becomes more well-known in the hacking world. As exploitation relies heavily on highly esoteric URL parsing techniques, a high-level mitigation may be appropriate to implement.

## Non-File Reverse Solidus Path URL Strings

Similar to the example before, the following values for the `articleValue` parameter can be seen as they are set, versus how they are requested for the browser.

| Example # | `articleName` | Request URL |
|-|-|-|
| 1 | `..\..\dynamic\user-uploads\malicious-file.png` | `https://example.com/dynamic/user-uploads/malicious-file.png` |
| 2 | `..%5C..%5Cdynamic%5Cuser-uploads%5Cmalicious-file.png` | `https://example.com/dynamic/user-uploads/malicious-file.png` |

As we see above, the reverse solidus (`\`) character is treated by WHATWG's URL standard as an [invalid but not terminating](https://url.spec.whatwg.org/#invalid-reverse-solidus) path segment. This means, it is treated the same as the forward solidus (`/`).

In various public cases, the incorrect technique of only escaping or removing forward solidus' from paths has [been the source of vulnerabilities](https://medium.com/@renwa/client-side-path-traversal-cspt-bug-bounty-reports-and-techniques-8ee6cd2e7ca1).

The vast majority of websites do not rely on this functionality (if any, which are non-local), and it has been proven to be an edgecase that is unsafely handled by developers.

# Proposed Solutions
## New CSP Expressions

The Content-Security-Policy is a perfect fit for disabling and enabling the functionality that has been outlined above. With new CSP expressions for each valid directive, webmasters may communicate to the browser whether they intend to use double-dot path shortening or not, and in which context.

At the time of writing this, available CSP directives that this issue pertains to are: `script-src style-src img-src connect-src object-src frame-src child-src form-action frame-ancestors base-uri worker-src manifest-src prefetch-src`, and a default `default-src`.

This proposal suggests that each of these directives may include the expressions `no-shortening` and `no-reverse-solidus`, which disable the canonization methods outlined above.

For example, it _is_ a common pattern to use the double-dot shortening to retrieve static files such as css files, javascript files, and image files, relative to the path a page is viewed on. For example:

### `no-shortening` CSP Expression

This expression may be used to disable the double-dot path shortening by the respective functionality of the browser, congruent to the CSP directive it is applied to. For example, if under no circumstanes should an image ever be loaded on a page using double-dot path shortening, a `Content-Security-Policy: img-src 'no-shortening';` header would ensure that if code such as:

```html
<img src="https://example.com/dir1/../dir2/foo.jpg" alt="example picture" />
```
was ever encountered, the resource would not be attempted to be loaded. Instead of shortening the path, the browser would terminate the parsing.

A complementary `allow-shortening` expression would leave current path parsing as-is.

### `no-reverse-solidus` CSP Expression

This expression may be used to disable the non-termination of the invalid reverse-solidus usage. As above, for a CSP policy such as `Content-Security-Policy: connect-src 'no-reverse-solidus';`, the code:

```js
const retrievedItem = await fetch("https://example.com/dir1\dir2");
```
would be terminated during the URL parsing stage, instead of the current functionality of treating the `\` as `/`.

A complementary `allow-reverse-solidus` expression would leave current path parsing as-is.

## Limitations

There are various limitations and pitfalls arising from this proposal.

### Server-Side Path Decoding

A serious limitation to this proposal is that some webservers perform decoding of URL-encoded paths, either deliberately or erroneously. This means that a URL of `https://example.com/%2Fdir1%2F..%2Fdir2%2Ffoo.jpg` will be sent to the `example.com` server with the path `/%2Fdir1%2F..%2Fdir2%2Ffoo.jpg`, resulting in either a server-side redirect to `/dir2/foo.jpg`, or simply the file itself. Whether this is intended by webmasters or not is questionable, as it consequentially denies the ability for files to be retrieved from the affected websites if they include `/..` in their name (as the server will treat decoded or encoded versions of the filename as a shortening).

From a list of "the safe-for-work top-100 most visited websites in November 2024" (whether it's correct or not), a total of 51 websites automatically either redirected or served `robots.txt` when requesting the path `/dir1/../robots.txt` (see [Appendix](#double-dot-following-urls)), while a total of 27 websites automatically either redirected or served `robots.txt` when requesting for the path `/dir1%2F..%2Frobots.txt` (see [Appendix](#double-dot-encoded-following-urls)).

From the top-100 visited websites, `shopify.com` was the only website which exhibited "infinite decoding". For example:

```shell
$ echo https://www.shopify.com/dir1$(urlencode $(urlencode $(urlencode $(urlencode '/'))))..$(urlencode $(urlencode $(urlencode $(urlencode '/'))))robots.txt
https://www.shopify.com/dir1%2525252F..%2525252Frobots.txt
$ curl -L https://www.shopify.com/dir1$(urlencode $(urlencode $(urlencode $(urlencode '/'))))..$(urlencode $(urlencode $(urlencode $(urlencode '/'))))robots.txt
[robots.txt]
```

When requesting `/dir1\\..\\robots.txt`, 20 websites served `robots.txt` (see [Appendix](#invalid-reverse-soliud-following-urls)), but by requesting `/dir1%5C..%5Crobots.txt`, just 4 websites served `robots.txt` (see [Appendix](#invalid-reverse-solidus-encoded-following-urls)). Again, this means that on these websites, it is likely impossible to retrieve files which contain `\..` in their filename.

This limitation is not a limitation directly of the CSP expressions outlined in this document. If we go back to the previous example of vulnerable code and sanitize the `articleName` using `URLSearchParams()` as so:

```js
        async function loadArticle() {
            const articleName = new URLSearchParams(window.location.search).get('articleName');
            
            const articleUrl = `https://example.com/static/article/{URLSearchParams($articleName)}`;
            const response = await fetch(articleUrl);
            const articleHtml = await response.text();
            
            document.getElementById('content').innerHTML = articleHtml;
        }
```

the code is _still_ vulnerable, if `articleName` is double encoded: `encode(encode("../../robots.txt"))` or `..%252F..%252Frobots.txt`. Ultimately, `fetch("https://example.com/static/article/..%2F..%2Frobots.txt")` will be executed, with the path set to `static/article/..%2F..%2Frobots.txt`. 27 of the top-100 websites will still serve `/robots.txt`. Other than an architectural change, what could a developer do? Other than loop over the path with `decodeURIComponent()` and stop when there are no differences between two iterations (and hope that `decodeURIComponent()` ultimately parses the path the same way as the browser does), not much can be done.


# What Will This Break?
## Languages Without Canonicalization

Some websites rely on relative paths (beginning or not) with `../` to import resources such as css, javascript, and font files, on webpages. These websites are reguarley developed using languages that do not provide standard functions to calculate absolute paths or that can canonicalize URLs. For example, PHP does not provide any standard function that can convert `/dir1/../dir3` into `/dir3`, and developers are left with the task of [creating their own implementation](https://www.php.net/manual/en/function.realpath.php#84012). Websites like this would benefit from the `allow-shortening` expression.

# Appendix

## Double Dot Following URLs

`curl --path-as-is -L "https://www.${URL}/dir1/../robots.txt"`
```
msn.com
youtube.com
google.com
x.com
twitter.com
duckduckgo.com
taboola.com
wikipedia.org
bing.com
chatgpt.com
quora.com
twitch.tv
naver.com
baidu.com
vk.com
canva.com
discord.com
spotify.com
globo.com
pinterest.com
github.com
mail.ru
doubleclick.net
imdb.com
bit.ly
roblox.com
zoom.us
instructure.com
booking.com
foxnews.com
onlyfans.com
aliexpress.com
ebay.com
deepl.com
adobe.com
manganato.com
speedtest.net
wordpress.com
stackoverflow.com
detik.com
character.ai
snapchat.com
nih.gov
samsung.com
okta.com
shein.com
line.me
medium.com
figma.com
ok.ru
yelp.com
```
## Double Dot Encoded Following URLs

`curl --path-as-is -L "https://www.${URL}/dir1%2F..%2Frobots.txt"`

```
wikipedia.org
taboola.com
duckduckgo.com
msn.com
naver.com
vk.com
quora.com
aliexpress.com
github.com
globo.com
mail.ru
bit.ly
samsung.com
instructure.com
booking.com
adobe.com
manganato.com
imgur.com
foxnews.com
deepl.com
wordpress.com
speedtest.net
character.ai
detik.com
ok.ru
shein.com
okta.com
```

## `invalid-reverse-solidus` Following URLs

`curl --path-as-is -L "https://www.${URL}/dir1\..\robots.txt"`

```
google.com
youtube.com
instagram.com
chatgpt.com
msn.com
pinterest.com
discord.com
canva.com
globo.com
spotify.com
doubleclick.net
ebay.com
bit.ly
onlyfans.com
character.ai
snapchat.com
stackoverflow.com
shopify.com
medium.com
figma.com
```

## `invalid-reverse-solidus` Encoded Following URLs

`curl --path-as-is -L "https://www.${URL}/dir1%5C..%5Crobots.txt"`

```
bing.com
msn.com
bit.ly
character.ai
```
