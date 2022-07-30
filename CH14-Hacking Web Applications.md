{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH14-Hacking Web Applications
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/29(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 連線劫持(Session Hijacking)
> 目的: 取得 Session

---

## Web Application Concepts
> This section describes the basic concepts associated with web applications vis-à-vis security concerns—their components, how they work, their architecture, and so on. Furthermore, it provides insights into web services and vulnerability stacks.


### web service v.s. web application
#### Web service 
> 目的：用web技術做分散式運算
- soap: 跑XML
- Restful



|        | Web Application                                                                                                                             | Web Service                                                                                                                                                                                        |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 相同點 | 1. 都使用HTTP来传输数据 <br>2. 都使用HTTP的认证/授权功能来保证数据安全。 <br>3. 一般来说都被托管在Web Server上。                            | 1. 都使用HTTP来传输数据 <br>2. 都使用HTTP的认证/授权功能来保证数据安全。 <br>3. 一般来说都被托管在Web Server上。                                                                                   |
| 相異點 | 1. 对Web Application发起的请求，一般直接返回HTML或者图像数据等等。<br>2. 从Web Application得到的结果一般都是通过Web Browser直接展示给用户。 | 1. 对Web Service发起的请求，一般来说返回的都是XML，JSON。 <br>2. 从Web Service的得到的数据都是原始结构，一般不直接展示给用户。 <br>3. Web Service的作用一般是为Web Application提供某些服务和接口。 |

|            | Web Service (API)         | Web Application  |
|:---------- |:-------------------- |:---------------- |
| 服務對象     | 程式/軟體             | 人類             |
| 描述語言   | XML                  | HTML             |
| 服務的檢索 | 利用 UDDI 查詢       | 利用搜尋引擎查詢 |
| 通訊協定   | SOAP+HTTP/HTTPS/SMTP | HTTP/HTTPS       |

## Web Application Threats
### OWASP TOP 10 Application Security Risks - 2017
- 開放網路軟體安全計畫，簡稱OWASP （Open Web Application Security Project）是一個開放社群、非營利性組織
1. A01-Injection 注入攻擊
    - 根據後端是甚麼系統
    - OS Command Injection
    - 攻擊者想要串接的語法到後端，在後端環境執行
    - ex. 在前台使用 
        ```shell=
        ping | whoami
        ```
    - 在後端就可以執行**whoami**
    - 攻擊手法: 塞程式碼
2. A02-Broken Authentication 無效身分認證
    - 破碎身分鑑別
    - Session ID in URLs
    - Password Exploitation
    - TimeoutExploitation
    - 攻擊手法: 偷身分
3. A03-Sensitive Data Exposure 敏感資料外洩
    - 不使用或傳送時的資料必須加密導致敏感資料外洩
4. A04-XML External Entity (XXE) XML外部處理器漏洞
    - on XML
    - access protected files and services
5. A05-Broken Access Control 無效的存取控管
    - 破碎存取控制
    - 攻擊手法: 不該被存取的資料被存取
6. A06-Security Misconfiguration 不安全的組態設定
    - 該設定沒設定好
    - ex. 網站錯誤測試 [testfire](testfire.net)
    - ex. SSL測試 [ssltest](https://www.ssllabs.com/ssltest/)
    - Unvalidated Inputs
        - 輸入帳號int 改成string
    - Parameter/Form Tampling
        - 輸入帳號108000000->改成108000001看到別人的
    - Improper Error Hanlding
        - 噴錯
    - Insufficient Transport Layer protection
        - 加密等級不夠
        - ssltest
7. A07-Cross-Site Scripting (XSS) 跨站攻擊
    - 驗證或傳輸不當 導致使用者的 Session 被劫持
    - 跨站腳本文本(攻擊user)
    - 透過email
    - 透過網站本身的寫入功能
8. A08-Insecure Deserialization 不安全的解序列化
    :::info
    ### serialization v.s. Deserialization
    1. serialization
        > 序列化
        > 是將物件狀態轉換為`可保存`或`可傳輸格式`的形式。
        ```bash=
        <Employee>
            <Name>Rinni</Name>
            <Age>26</Age>
            <City>Nevada</City>
            <EmpID>2201 </EmpID>
        </Employee>
        ```  
    2. Deserialization
        > 反序列化
        > 則是序列化的相反，它可以將資料流轉換成物件。
        - 看上面的序列化去解析
        - 解法：放進去是怎樣，要檢查
    
    <img src="https://ithelp.ithome.com.tw/upload/images/20190927/20115060blg1OEgSyO.png" />
    :::

9. A09-Using Components with Known Vulnerablities 使用已有漏洞的元件
10. A10-Insufficient Logging and Montioring 記憶與監控不足

### Other Web Application Threats 
1. Directory Traversal
    - 路徑跨越
2. Unvalidated Redirects and Forwards
    - 未驗證的網站重新導向
    - ex. yahoo網站廣告
3. Watering Hole Attack
    > It is a type of unvalidated redirect attack whereby the attacker first identifies the most visited website of the target, determines the vulnerabilities in the website, injects malicious code into the vulnerable web application, and then waits for the victim to browse the website. Once the victim tries to access the website, the malicious code executes, infecting the victim.

    > 「水坑（Watering hole）」攻擊和我們一般認為的網路攻擊相反。並不是去攻擊目標，而是去埋伏在他們知道目標可能會去的地方。
    - 結合偷渡式下載
    - any possible vulnerabilities
    - attacker wait for the victim to fall into a trap
4. Cookies Poisioning
    - ex: Cooke bomb 
        - 塞很長的Cookie讓使用者去存取網站時被拒絕(通常是413 Request Header Fields Too Larg error)
    > 藉由修改cookies 值，來癱瘓網站的效果
    - ex. 天下雜誌
        - f12 storage 修改cookies 值
        - payword cookies 刪除就可以看到非會員的內容
5. Web Service Attacks
    - [Web service Web](https://www.capital.com.tw/WebService/WebService.asmx?op=HelloWorld)
6. Web Service XML Poisoning
7. Hidden Field Manupulation Attack
    - 有些網站會用 hidden input 傳資料 可以改裡面的值進行攻擊
    ```html=
    <input type="hidden"></input>
    ```
8. Web-based Timing Attacks
    > 網頁時序性攻擊
    > 程式的邏輯是先判斷account是否正確
    > 可以觀察account如果錯誤，會馬上跳轉
    > 如果正確，會在檢查密碼，所以等待的時間會稍久
<!--     - 如果寫程式的邏輯是先找帳號是否存在 看網頁跳掉的時間可知道帳號是否存在 -->
9. MarioNet Attack
    > Attacker abuse the Service Workers API to inject and run malicious code in the victim’s browser to perform various attacks such as cryptojacking, DDoS, click fraud, and distributed password cracking
    - 在F12應用程式，可以看到 service worker
    - 如果可以讓他離開網站後執行，電腦就會變成殭屍
    - 基於瀏覽器的攻擊，就算關掉網站感染仍存在
    - 簡單來說: 在使用者的瀏覽器種一個程式 讓他變殭屍
10. Clickjacking Attack
    - 以比較技術的講法來說，就是用 iframe 把 B 網頁嵌入然後設透明度 0.001，再用 CSS 把自己的內容疊上去，就大功告成了。
    - 綁架滑鼠攻擊
    - 使用者會不知道點了什麼
11. DNS Rebinding Attack
    - 認域名，所以可以假造域名，欺騙瀏覽器取得cookie、local storage、servce work達到攻擊的效果
    - 透過一個server向其他 VLAN 的機器要資料
    - 解決辦法: 同源策略(same-origin policy)
        - 東西誰放的，誰可以拿走

## Web Application Hacking Methodology
- Detecting Web App Firewalls and Proxies on Target Site
- Detecting Web Application Firewalls(WAFs)


### Analysis Web Application
常用工具：
- Burp Suite
- OWASP Zed Attack Proxy
- WebScarab
- httprint
#### Identify Server-Side Functionality
- 常用工具：Wrappalyzer

#### Identify Files and Directories (找網站的檔案路徑)
1. 常用工具：Gobuster
    > 路徑爆破
    - 原理:字典檔
    ```shell=
    gobuster -u <target URL> -w common.txt -s 200
    ```
3. 常用工具：Nmap
    - Nmap NSE script http-enum
    ```shell=
    nmap -sV --script=http-enum <target domain or IP address>
    ```

### Bypass Client-side Controls
#### Attack Hidden Form Fields
- OSWAP 2017 risks 的第7個
>  Identify hidden form fields on the web page and manipulate the tags and fields to exploit the web page before transmitting the data to the server.
#### Attack Browser Extensions
>  Attempt to intercept the traffic from the browser extensions or decompile the browser extensions to capture user data.
- ex: bicode->decompile
#### Perform Source Code Review
>  Perform source code review to identify vulnerabilities in the code that cannot be identified by traditional vulnerability scanning tools.
- 直接看 source 找漏洞
#### Evade XSS Filters
> Evade XSS filters by injecting unusual characters into the HTML code.
> 繞過過濾機制
-  使用編碼字元，多空白。 讓偵測機制忽略，但在讀的時候是惡意程式碼

## Password Attacks
### Password Functionality Exploits
- Password Changing
- Password Recovery
- Remember me
### Password Guessing
- Password List 
- Password Dictionary
- Tools 
    - THC-Hydra Source: https://www.thc.org

###  Brute-forcing
Password Cracking Tools Some brute-forcing tools for cracking passwords are described below.  Burp Suite
## Web Services APIs
||REST|SOAP|
|:--|:--|:--|
|優點|1.提供更多元資料格式(因為基於JSON) <br> 2. 優越的性能。特別指快取資料。|1.方便通過防火牆和Proxy<br>而不對協定本身進行修改。<br>*對大企業而言穩定安全最重要|
- restful 就是有良好規範的 REST (在HTTP中即 GET/POST/PUT/DELETE)
1. SOAP API
    - enable interactions
2. Rest API
    - communication medium
3. Restful API
    - Rest principle and HTTP communication protocols
4. XML-RPC
    - uses a specific XML format
5. JSON-RPC
    - uses JSON format


### Webhooks
- 一種回call機制
- user-defined HTTP callback
- EX: Line

### Fuzzing
- send random input to the target API
- 隨便塞input，回傳error，觀察error

### Login/Credential Stuffing Attacks
- crediential stuffing attacks
- 利用帳密(用已經知道外洩)的填充(try IG、facebook)
- ex: 可能有些人不同帳號(FB IG)用一樣的帳號密碼

### Web Shells
- gain remote access
- inject malicious code

```shell=
weevely generate 123 web.php
```
> 目的：中下遠端後門


### **bug bounty program**
:::danger
考試會考
:::
> 獎金獵人公司


## CH14 Practice
1. [Lab2-1] Perform a Brute-force Attack using Burp Suite
2. [Lab2-6] Exploit a Remote Command Execution Vulnerability to Compromise a Target Web Server

