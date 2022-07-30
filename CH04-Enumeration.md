{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH04-Enumeration
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/15(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 枚舉（Enumeration）
> 滲透測試通常在收集信息/情報，掃描IP，確定設備和操作系統的類型，> > 掃描端口並發現可用服務之後，枚舉由主機上的服務提供的資源。

---

## Security Events
- [漏洞通報網站-Zeroday](https://zeroday.hitcon.org/vulnerability)
    - git leak: 設定上的問題
    - XSS, SQL injection: 程式沒寫好

## Enumeration Concepts
### What is Enumeration?
> Enumeration 
> is the process of extracting usernames, machine names, network resources, shares, and services from a system or network. 

> In the enumeration phase, an attacker creates active connections with the system and sends directed queries to gain more information about the target. 

> The attacker uses the information collected using enumeration to identify vulnerabilities in the system security, which help them exploit the target system. 

> In turn, enumeration allows the attacker to perform password attacks to gain unauthorized access to information system resources. Enumeration techniques work in an intranet environment.

### enumeration allows the attacker to collect the following information: 
- Network resources 
- Network shares 
- Routing tables 
- Audit and service settings 
- SNMP and fully qualified domain name (FQDN) details 
- Machine names 
- Users and groups 
- Applications and banners

## Enumeration
### Techniques for Enumeration
1. Extract usernames using email IDs
2. Extract information using default passwords
3. Brute force Active Directory
4. Extract information using DNS Zone Transfer
5. Extract user groups from Windows
6. Extract usernames using SNMP

### Services and Ports to Enumerate
|  Type   |      Port      | Name                                         |
|:-------:|:--------------:|:-------------------------------------------- |
|   TCP   |     20/21      | File Transfer Protocol                       |
|   TCP   |       22       | Secure Shell (SSH)                           |
|   TCP   |       23       | Telnet                                       |
|   TCP   |       25       | Simple Mail Transfer Protocol (SMTP)         |
| TCP/UDP |       53       | DNS Zone Transfer                            |
|         |       80       | HTTP                                         |
|   UDP   |      123       | Network Time Protocol (NTP)                  |
| TCP/UDP |      135       | Microsoft RPC Endpoint Mapper                |
|   UDP   |      137       | NetBIOS Name Service (NBNS)                  |
|   TCP   |      139       | NetBIOS Session Service (SMB over NetBIOS)   |
|   UDP   |      161       | Simple Network Management Protocol (SNMP)    |
| TCP/UDP |      162       | SNMP Trap                                    |
| TCP/UDP |      389       | Lightweight Directory Access Protocol (LDAP) |
|         |      443       | https                                        |
| TCP/UDP |      445       | SMB over TCP (Direct Host)                   |
|   UDP   |      500       | ISAKMP/Internet Key Exchange(IKE)            |
|   TCP   |      2049      | Network File System (NFS)                    |
|         | 515, 631, 9100 | Printer                                      |
 
### NetBIOS Enumeration
> NetBIOS(Network Basic Input/Output System)
> 可以把它想成是一種多台電腦組成的小型區域網路
```shell
nmap -sV -v --script nbstat.nse <target ip address>
```
:::danger
NetBIOS會使用TCP/IP來標示網路設備，並由ASCII組成16個字符
前15個字符為設備名稱，第16個字符會標識服務類型與NetB
- 16ASCII character 1~15:電腦名 16:服務名(代號)
:::

:::info
常用指令/工具：nbtstat、Hyena、Superscan
:::


### SNMP Enumeration
> SNMP(Simple Network Management Protocol)
> 是存在於應用層中的簡單網路管理通訊協定，管理網路設備之間(如路由器、交換器、hub)的資訊，其可以監控比較細部的設備資訊及硬體資訊，如記憶體、CPU。
```shell
snmp-check 10.10.10.10
```
> 攻擊者可以透過列舉SNMP來取得目標系統的密碼、系統名稱、設備、使用者帳戶等。
:::info
常用工具：Snmpcheck、OpUtils、SolarWinds
:::


### LDAP Enumeration
> LDAP(Lightweight Directory Access Protocol)
> 是一個輕量級目錄訪問的協議

> 攻擊者可以透過列舉LDAP來取得Server names、部門資訊，地址、使用者名稱。

:::info
常用工具：jxplorer、Softerra LDAP Administrator
:::

### NFS enumeration
> NFS(Network File System)


:::info
常用工具：SuperEnum、RPCScan
:::

- 要設權限
- 不然資料會看光

### SMTP Enumeration
> SMTP ( Simple Mail Transport Protocol)
> 可以在大多數的電腦中找到此服務，攻擊者可以透過列舉SMTP，來取得服務上的用戶資訊，如驗證用戶、查詢郵件列表與其要傳送到的位址、定義收件者。
:::info
常用指令：VRFY、EXPN、RCPT TO
:::

#### SMTP provides the following three built-in commands.
1. VRFY: Validates users
    - 連上192.168.168.1 port 25
        ```shell=
         telnet 192.168.168.1 25
        ```
    - 驗證使用者
        ```shell=+
        VRFY Jonathan
        ```
        ```text=
            250 Super-User <Jonathan@NYmailserver> 
        ```
    
2. EXPN: Displays the actual delivery addresses of aliases and mailing lists 
     - 連上192.168.168.1 port 25
        ```shell=
         telnet 192.168.168.1 25
        ```
    - 顯示真實傳送地址
        ```shell=+
        EXPN Jonathan
        ```
        ```text=
            250 Super-User <Jonathan@NYmailserver> 
        ```
3. RCPT TO: Defines the recipients of the message 
    - 連上192.168.168.1 port 25
        ```shell=
         telnet 192.168.168.1 25
        ```
    - 決定接受者
        ```shell=+
        MAIL FROM:Jonathan 
        ```
        ```text=
            MAIL FROM:Jonathan 
        ```
        - 有回覆
            ```shell=+
            RCPT TO:Ryder
            ```
            ```text=
                250 Ryder... Recipient ok
            ```
        - 沒回覆
            ```shell=+
            RCPT TO: Smith
            ```
            ```text=
                550 Smith... User unknown
            ```

:::info
常用工具： NetScanTools Pro、 smtp-user-enum
:::

### DNS cache Snooping
:::danger
必考
:::

> **藉由查詢快取解析曾經那些名稱**

> DNS cache snooping
> is a type of DNS enumeration technique in which an attacker queries the DNS server for a specific cached DNS record. By using this cached record, the attacker can determine the sites recently visited by the user. This information can further reveal important information such as the name of the owner of the DNS server, its service provider, the name of its vendor, and bank details. By using this information, the attacker can perform a social engineering attack on the target user. 

#### 兩種查詢方法
1. 非遞迴查詢(Non-recursive Method)
    > In this method, to snoop on a DNS server, attackers send a non-recursive query by setting the Recursion Desired (RD) bit in the query header to zero.
    - 公式
        ```shell=
        dig @<IP of DNS server> <Target domain> A +norecurse
        ```
    - example
        ```shell=
        dig @162.159.25.175 certifiedhacker.com A +noercurse
        ```
    
2. 遞迴查詢(Recursive Method)
    > In this method, the time-to-live (TTL) field is examined to determine the duration for which the DNS record remains in the cache. 
    - 公式
        ```shell=
        dig @<IP of DNS server> <Target domain> A +recurse
        ```
    - example
        ```shell=
        dig @162.159.25.175 certifiedhacker.com A +recurse
        ```

### DNSSEC Zone Walking 
:::danger
考試會考
:::
> Domain Name System Security Extensions (DNSSEC) zone walking
>  is a type of DNS enumeration technique in which an attacker attempts to obtain internal records if the DNS zone is not properly configured. 

>  The enumerated zone information can assist the attacker in building a host network map.

<img src="https://blog.twnic.tw/wp-content/uploads/2020/06/%E5%9C%967-800x487-1.png" />

:::info
常用工具： LDNS、DNSRecon
:::

## Other Enumeration Techniques
### IPsec Enumeration
:::danger
常考
:::
> 網際網路安全協定（英語：Internet Protocol Security，縮寫：IPsec）
> 是一個協定套件，透過對IP協定的封包進行加密和認證來保護IP協定的網路傳輸協定族（一些相互關聯的協定的集合）

> IPsec
> is the most commonly implemented technology for both gateway-to-gateway (LAN-to-LAN) and host-to-gateway (remote access) enterprise VPN solutions. 
> IPsec provides data security by employing various components such as Encapsulating Security Payload (ESP), Authentication Header (AH), and Internet Key Exchange (IKE) to secure communication between VPN endpoints.

- IPsec主要由以下協定組成：
    1. 認證頭（AH），為IP資料報提供無連接資料完整性、訊息認證以及防重放攻擊保護；
    2. 封裝安全載荷（ESP），提供機密性、資料來源認證、無連接完整性、防重放和有限的傳輸流（traffic-flow）機密性；
    3. 網際網路金鑰交換（英語： Internet Key Exchange ，簡稱IKE或IKEv2），為 AH、ESP 操作所需的 安全關聯（SA） 提供演算法、封包和金鑰參數。

:::warning
補充資料
- **ESP transport mode** should be used to ensure the integrity and confidentiality of data that is exchanged within the same LAN. 
- **AH transport** would only ensure the integrity of the LAN data, not the confidentiality
- **ESP tunnel mode** should be used to secure the integrity and confidentiality of data between networks and not within a network
- **AH tunnel mode** should be used to secure the integrity of data between networks and not within a network
:::


:::info
常用工具： ike-scan
:::

### VoIP Enumeration
- Voice over Internet Protocol (VoIP)
>是一種語音通話技術，經由網際協定（IP）來達成語音通話與多媒體會議，也就是經由網際網路來進行通訊
```shell
svmap 10.10.10.10
```
:::info
常用工具： Svmap
:::

### RPC Enumeration
```shell
nmap -sR
```
> The remote procedure call (RPC)
> is a technology used for creating distributed client/server programs.

> 遠端程序呼叫
:::info
常用工具： NetScanTools Pro
:::

## CH04 Practice
1. [Lab 1.1] Perform NetBIOS Enumeration using Windows Command-Line Utilities
2. [Lab 2.1] Perform SNMP Enumeration using snmp-check
3. [Lab 3.1] Perform LDAP Enumeration using Active Directory Explorer (AD Explorer)
4. [Lab 4.1] Perform NFS Enumeration using RPCScan and SuperEnum
5. [Lab 5.1] Perform DNS Enumeration using Zone Transfer

