{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH11-Session Hijacking
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/29(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 123
---

## Session Hijacking Concepts
### What is Session Hijacking
- 一般機器只會在建立連線時進行身分驗證，只要偷盜驗證的session就可以假冒身分
> A web server sends a session identification token or key to a web client after successful authentication. These session tokens differentiate multiple sessions that the server establishes with clients. Web servers use various mechanisms to generate random tokens and controls to secure the tokens during transmission. 
> **Session hijacking is an attack in which an attacker takes over a valid Transmission Control Protocol (TCP) communication session between two computers.** Because most types of authentication are performed only at the start of a TCP session, an attacker can gain access to a machine while a session is in progress. Attackers can sniff all the traffic from established TCP sessions and perform identity theft, information theft, fraud, etc.

### TCP/IP Session Hijacking Process
1. sniff
2. monitor
3. session desynchronization(把別人斷線)
4. session ID prediction
5. command injection(可以控制對方cmd)

### Types of Session Hijacking
1. Passive Session Hijacking 
    - hijack session
2. Active Session Hijacking
    > In an active attack, an attacker takes over an existing session either by breaking the connection on one side of the conversation or by actively participating.
    - In an active attack, an attacker finds an active session and seizes control of it

### Session Hijacking in OSI Model
1. Network Level Hijacking
    > Network level hijacking 
    > is the interception of packets during the transmission between a client and server in a TCP/User Datagram Protocol (UDP) session. A successful attack provides the attacker with crucial information, which can be further used to attack application level sessions. 
2. application Level Hijacking
    > Application level hijacking 
    > involves gaining control over the Hypertext Transfer Protocol (HTTP) user session by obtaining the session IDs. 

### Spoofing vs Hijacking
- Spoofing attack 
    - 身分冒用(假冒身分)
    - **pretends to be another user**
    - stolen credentials
    - foodpanda送餐，送餐給A，冒用B的身分點餐
- Hijacking
    - 劫持
    - **existing active session**
    - legitimate user
    - foodpanda，送餐送給A，但是等A去查看餐點不見了

## Application Level session Hijacking
:::danger
考試必考
:::

A session token can be compromised in various ways
1. Session sniffing 
2. Predictable session token 
3. Man-in-the-middle (MITM) attack 
4. Man-in-the-browser attack 
5. Cross-site scripting (XSS) attack 
6. Cross-site request forgery attack
7. Session replay attack 
8. Session fixation attack 
9. CRIME attack 
10. Forbidden attack 
11. Session donation attack


### 1. Session sniffing 
> An attacker uses packet sniffing tools such as Wireshark and SteelCentral Packet Analyzer to intercept the HTTP traffic between a victim and web server. **The attacker then analyzes the data in the captured packets to identify valuable information such as session IDs and passwords.**

### 2. Predictable session token 
> An attacker collect a high number of simultaneous session IDs to gather samples in the same time window and keep the variable constant. First, the attacker collects some valid session IDs that are useful in identifying authenticated users. The attacker then studies the session ID structure, the information used to generate it, and the algorithm used by the web application to secure it. From these findings, the attacker can predict the session ID.
- 透過日期時間製作session
- 就是用猜的
### 3. Man-in-the-middle (MITM) attack
> A man-in-the-middle (MITM) attack is used to intrude into an existing connection between systems and to intercept messages being transmitted. 
- 侵入 server 和 target 已經建立的連線

### 4. Man-in-the-browser attack 
> man-in-the-browser attack uses a Trojan horse to intercept and manipulate calls between a browser and its security mechanisms or libraries.
- uses Trojan horse
- 透過瀏覽器的外掛，可能會被中後門
- 瀏覽器種惡意外掛
### 5. Cross-site scripting (XSS) attack
:::danger
XSS喜歡和CSRF一起考
:::
>  A cross-site script attack is a client-side attack in which the attacker compromises a session token by using malicious code or programs. This type of attack occurs when a dynamic web page receives malicious data from the attacker and executes it on the user’s system.

- session：是存在瀏覽器的cookies
- XSS目的：可以拿到別人的cookies
- firefox，f12->可以看到PHPSESSID
    ```html=
    <SCRIPT>alert(document.cookie);</SCRIPT>
    ```

### 6. Cross-site request forgery(CSRF) attack
:::danger
跨站假造請求(CSRF)->通常這個是答案
:::
> Cross-site request forgery (CSRF), also known as a **one-click attack** or **session riding**, is an attack in which the **attacker exploits the victim’s active session with a trusted site to perform malicious activities** such as item purchases and the modification or retrieval of account information. 

> 舉個例子:
> 陌生人＝ Hacker 菜單 ＝ Request
> 桌號＝ cookie 老闆＝ web server 你 ＝ User
> 想像你到一家餐廳吃飯，陌生人拿了一張有你桌號的菜單點餐之後給老闆，結果老闆問也不問便收了菜單並將帳記到了你的身上，這就是 CSRF 的基礎概念。
:::info
#### XSS v.s. CSRF
> 最大的差異：攻擊對象的不同

|          | 跨站請求(XSS) | 跨站腳本(CSRF)       |
|:-------- |:------------- |:-------------------- |
| 攻擊對象 | 攻擊網站      | 攻擊user             |
| 攻擊方式 | 攻擊瀏覽器    | 透過你的電腦攻擊別人 |
|過程|攻擊網站，讓使用者感染惡意程式碼|攻擊user，用user的身分對網站存取|
|例子|![](https://i.imgur.com/U6Rw8dh.jpg)|![](https://i.imgur.com/nWX162e.jpg)

:::
   
### 7. Session replay attack
> 重放攻擊
- attacker 偷聽到認證的 token 拿去給 server 驗證
> In a session replay attack, the attacker captures the authentication token of a user by listening to a conversation between the user and server.

### 8. Session fixation attack 
> The attacker performs a session fixation attack to hijack a valid user session. The attacker takes advantage of limitations in web-application session ID management.
- ex: 如果 userid 存在 url (像是 http://unsafebank.com/login.php?sid=1234) attacker 在 user 登入後就可以用這個系統發的url假冒使用者

### 9. CRIME attack 
> Compression Ratio Info-Leak Made Easy (CRIME) 
> is a client-side attack that exploits vulnerabilities in the data-compression feature of protocols such as SSL/Transport Layer Security (TLS), SPDY, and HTTP Secure (HTTPS). The possibility of mitigation against HTTPS compression is low, which makes this vulnerability even more dangerous than other compression vulnerabilities.
> 此漏洞立足於選擇明文攻擊配合資料壓縮無意間造成的資訊泄露。它依賴於攻擊者能觀察瀏覽器傳送的密文的大小，並在同時誘導瀏覽器發起多個精心設計的到目標網站的連接。攻擊者會觀察已壓縮請求載荷的大小，其中包括兩個瀏覽器只傳送到目標網站的私密Cookie，以及攻擊者建立的變數內容。當壓縮內容的大小降低時，攻擊者可以推斷注入內容的某些部分與源內容的某些部分匹配，其中包括攻擊者想要發掘的私密內容。使用分治法技術可以用較小的嘗試次數解讀真正秘密的內容，需要恢復的位元組數會大幅降低。
- 藉由HTTP壓縮的資料(壓縮率)還原/回推資料
### 10. Forbidden attack 
> A forbidden attack 
> is a type of MITM attack that can be executed when a cryptographic nonce is reused while establishing an HTTPS session with a server. 
- 中間人攻擊的一種，透過TLS協定的漏洞，如果 Nonce 重複使用會讓加密結果可觀測
- Nonce: number only use once
### 11. Session donation attack
:::danger
通常session donation attack 是答案
:::
- attacker 直接拿可用的 session 讓 user 去跟 server 做身分驗證
> In a session donation attack, the attacker donates their own session ID to the target user. In this attack, the attacker first obtains a valid session ID by logging into a service and later feeds the same session ID to the target user.



## Network level Session Hijacking
The following are different types of network level hijacking: 
1. Blind hijacking
2. UDP Hijacking
3. TCP/IP Hijacking
4. RST hijacking 
5. Blind and UDP Hijacking
6. Man-in-the-middle: packet sniffer
7. IP Spoofing: Source routed packets

### 4. RST hijacking 
- 讓人家斷線

### 5. Blind and UDP Hijacking
- Blind Hijacking
- UDP Hijacking

## Session Hijacking Tools
### Session Hijacking Tools for PC
1. Burp Suite Source: https://portswigger.net 
2. **OWASP ZAP** (https://www.owasp.org) 
3. bettercap (https://www.bettercap.org)
4. netool toolkit (https://sourceforge.net) 
5. WebSploit Framework (https://sourceforge.net) 
6. **sslstrip** (https://pypi.python.org)

### Session Hijacking Tools for Mobile Phones 
1. DroidSheep Source: https://droidsheep.info
2. DroidSniff Source: https://github.com
3. FaceNiff Source: http://faceniff.ponury.ne


## Countermeasures
### Session Hijacking Detection Methods
- Manual Method
    - Using Packeting Sniffing Software
- Automatic Method
    - Instrusion Detection System(IDS)
    - Instrucion Prevention System(IPS)

### Protecting against Session Hijacking
> 防治

常用的防治方式
1. HTTP StrictTransportSecurity(HSTS)
    > 嚴格HTTP
2. Token Binding
    > 把Token 加密
3. HTTP Public Key Pinning(HPKP)
    > 把server端的憑證寫死在client

:::info
IPsec (IP Security Protocol) 有時會考
:::

## LAB
### TCP/IP Session Hijacking
1. 在ubuntu 下載telent
    ```shell=
    sudo apt install telnet
    ```

2. 在parnet 下載 hunt-1.5bin.tgz，[下載位置](https://packetstormsecurity.com/files/21968/hunt-1.5bin.tgz.html)

    > 透過telnet控制對方，達成TCP/IP session 劫持

    - 解壓縮
    - 另一台telnet 可以看到

### Sniffing
> 目的：偷到PHPSESSID token
1. 開啟 windows server 2016
    - 下載wireshark
    - 在wireshark 下 tcp port 8080
    - follow TCP stream
    - 可以看到PHPSESID是固定的
2. 開一般的首頁
    - 在瀏覽器下
    - 10.10.10.16:8080/dvwa/login.php
    - f12 Storage
    - 修改PHPSESSID
    - PHPSESSID 把windows server 2016 看到的複製貼上
    - 輸入10.10.10.16:8080/dvwa/

    :::info
    ### 步驟 
    用wireshark側錄 follow->tcp stream->使用者端 發現SESSID是固定的 手動放到session
    - ex: 撿到的電影票
    - sniffing
    :::


## CH11 Practice
1. [1-1] Hijack a Session using Zed Attack Proxy (ZAP)