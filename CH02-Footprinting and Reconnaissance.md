{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH02-Footprinting and Reconnaissance
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/01(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |
## 文章
### 目錄
[TOC]

### 概要
> 章節: 情蒐與勘查

---

## Footprinting Methodology

- Footprinting through search engines 
     - Footprinting through web services 
     - Footprinting through social networking sites 
     - Website footprinting 
     - Email footprinting 
     - Whois footprinting 
     - DNS footprinting 
     - Network footprinting 
     - Footprinting through social engineering
### Footprinting through Search Engines
:::danger
考試會考
:::
1. index of (目錄瀏覽模式)
    - ex: [海大目錄瀏覽模式](http://www.alumni.ntou.edu.tw/admin/sop/)
2. site: edu.tw 限縮範圍
    - "-" 扣掉關鍵字
    - EX: index of /admin site:edu.tw -ntou
    ![](https://i.imgur.com/ePo6bjx.png)

3. intitle (在標題頁面做搜尋)
4. inurl (在網址頁做搜尋)
    - 搜尋關鍵字在url裡的
    - EX: site:edu.tw inurl:admin.php
5. intext (在網頁的部分做搜尋) 
6. filetype
    - EX: filetype:pdf site:edu.tw


### Other Techniques for Footprinting through Search Engines
> 其他搜查工具 

#### ghdb (google hacking database)
> ghdb->google hacking database
> google hacking 的操作步驟
    https://i.imgur.com/7blqIZd.jpg

### Finding a Company’s Top-Level Domains (TLDs) and Sub-domains

- sublist3r (to enumerating the subdomains of target company)
    :::info
     使用工具: Sublist3r，[Github-Sublist3r](https://github.com/aboul3la/Sublist3r)
    :::

    - sublist3r，參數 
        - -d domain
        - -b bruteforce
        - -p ports
        - -v verbose
        - -t threads
        - -e engines
        - -o output
        - -h help
    - ex: 
        ```shell=
        sublist3r -d google.com -p 80 -e Bing
        ```

- Pentest-Tools Fing Subdomains
    - https://pentest-tools.com
    - 網頁版的 也是找subdomain

### meta search engine
> meta search engine->元搜尋引擎
> 用搜尋引擎搜尋的搜尋引擎

### dnsdumpster
> 用伺服器查地理位置

### SNS
> SNS->social networking sites
> 用社群網站找人

## Deep and Dark Web Footprinting
- Tor Browser
1. 深網
    > google 搜不到的內容
2. 暗網
    > 100%違法

### Gathering Information from LinkedIn
- 工具: theHarvester，[Github-theHarvester](https://github.com/laramies/theHarvester)
> 目的: 找個人資料的
```shell=
theHarvester -d microsoft -l 200 -b linkedin
```


### Determining the Operating System
- Netcraft
- shodan
    - 搜索接入網際網路的設備的搜尋引擎
    - 可以查server資訊
- Censys
- zmap.io
    - 掃Internet 所有IP

## Footprinting through Social Networking Sites

### buzzsumo 
> 找人的
- https://buzzsumo.com
:::danger
會考
:::
> BuzzSumo's advanced social search engine finds the most shared content for a topic, author or a domain

### followerwonk 
> 也是找人的
- www.followerwonk.com
- 從追蹤者推出本人可能在哪個地區的網站
> Followerwonk helps to explore and grow one's social graph by digging deeper into Twitter analytics

## Tools For Footprinting through Social Networking Sites
### Sherlock
- $ python3 sherlock.py satya nadella
### Social Searcher
- https://www.social-searcher.com

## Website Footprinting 
> 網頁情蒐

Browsing the target website will typically provide the following information: 
- Software used and its version
- Operating system used
- Sub-directories and parameters
- Filename, path, database field name, or query
- Scripting platform
- Technologies Used
- Contact details and CMS details

### Burp Suite
> web 安全檢測

### Website Footprinting using Web Spiders


### Mirroring Entire Website
::: info
常用工具:  HTTrack Web Site Copier, [httrack](http://www.httrack.com)
:::
### Extracting Website Information from https://archive.org
> internet archive (網際網路檔時館，時光回朔機)

### Extracting Website Links
:::info
常用工具: Octoparse
:::
### Gathering Wordlist from the Target Website
:::info
常用工具: CeWL
:::
> 利用網站製作字典，產生密碼
- to show list of options
    ```shell
    ruby cewl.rb --help
    ```
- return unique words persent in the target website
    ```shell
    cewl www.certifiedhacker.com
    ```
- return list of words and email addresses
    ```shell
    cewl --email www.certifiedhacker.com
    ```

### Extracting Metadata of Public Documents
:::info
常用工具: metagoofil, [metagoofil]( https://code.google.com)
:::
> 取得public的所有文件

## Email Footprinting
### Collecting Information from Email Header
![](https://i.imgur.com/apn5Wjl.png)

### Email Tracking Tools
- infoga
    - [Source](https://github.com)
    - Implement
        ```shell=
        python infoga.py --domain microsoft.com --source all --breach -v 2 --report ../microsoft.txt
        ```
        will retrieve all the publicly available email addresses related to the domain microsoft.com along with email account information.
        ```shell=+
        python infoga.py --info m4ll0k@protonmail.com --breach -v 3 --report ../m4ll0k.txt
        ```
- eMailTrackerPro
    - [Source](http://www.emailtrackerpro.com)


## Whois Footprinting
### Whois Lookup
:::danger
 :warning: 必考
:::
- Regional Internet Registries(RIRs)
    > 目的: 查IP、查域名
- IP最初發放的五大地區
    | RIRs     | 地區     |
    | -------- | -------- |
    | ARIN     | 北美     |
    | AFRINIC  | 非洲     |
    | RIPE Ncc | 歐洲     |
    | LACNIC   | 拉丁美洲 |
    | APNIC    | 亞太     |

## DNS Footprinting
### Extracting DNS Information 
![](https://i.imgur.com/6cZqmb6.png)

## Network Footprinting
:::info
常用工具: traceroute (linux)；tracert(Windows)
:::
> Traceroute uses the ICMP protocol concept and Time to Live(TTL) field of the IP header to find the path of the target host in the network

## Footprinting through Social Engineering
> 社交工程
### Collecting Information
- Evasdropping 偷聽/竊聽
- ShoulderSurfing 窺視
- Dumpster Diving 翻垃圾桶
- Impersonation 假冒身分

### Footprinting Tools
1. Maltego(肉搜軟體)
    - [Source](https://www.paterva.com)
2. OSRFramework
    - [osint framework-肉搜懶人包](https://osintframework.com/)
    - 找人 找domain 都有
3. Recon-ng 
    - [Source](https://github.com)
4.  FOCA
    - [Source](https://www.elevenpaths.com)
5.  OSINT Framework
    - [Source](https://osintframework.com)
6.  Recon-Dog
    - [Source](https://www.github.com)
7. BillCipher
    - this tool includes :
        - DNS lookup
        - Whois lookup
        - zone transfer
        - host finder
        - reverse IP lookup




