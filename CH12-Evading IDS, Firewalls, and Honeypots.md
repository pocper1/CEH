{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH12-Evading IDS, Firewalls, and Honeypots
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/29(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 學習什麼是IDS, IPS, 以及如何規避防火牆的偵查
---

## IDS, IPS, Firewall, and Honeypot Concepts
> Ethical hackers should have an idea about the function, role, placement, and design of firewalls, IDS, IPS, and honeypots to protect an organization’s network by understanding how an attacker evades such security measures. This section provides an overview of these basic concepts. 


## IDS 
> 入侵偵測系統
> An intrusion detection system (IDS) 
> is a security software or hardware device used to monitor, detect, and protect networks or systems from malicious activities.

### How an IDS Detects an Instusion
- signature recognition
    > Signature recognition, 
    > also known as misuse detection, tries to identify events that indicate an abuse of a system or network.
    > 簽字識別 
- anomaly detection
    > Anomaly detection, or “not-use detection,” 
    > differs from signature recognition. Anomaly detection involves a database of anomalies. An anomaly is detected when an event occurs outside the tolerance threshold of normal traffic. Therefore, any deviation from regular use is an attack.
    > 異常檢測
- protocol anomaly Detection
    > Protocol anomaly detection depends on the anomalies specific to a protocol. 
    - TCP/IP specification 依照TCP/IP規則來操作
    
### Types of Intrusion Detection Systems
> 偵測入侵的程式
- Network-based Detection Systems 
    > Network-based intrusion detection systems (**NIDS**) 
    > check every packet entering the network for the presence of anomalies and incorrect data.
- Host-based Detection Systems 
    > A host-based IDS (**HIDS**)
    > analyzes each system’s behavior. The HIDS can be installed on any system ranging from a desktop PC to a server.



### types of IDS Alerts
|                                     | Attack | Alert |
| ----------------------------------- | ------ | ----- |
| True Positive(Attack - Alert)       | V      | V     |
| True Negative(No attack - No Alert) | X      | X     |
| False Positive(No Attack - Alert)   | X      | V     |
| False Negative(Attack - No Alert)   | V      | X     |




## IPS 
> 避免被入侵
> Intrusion Prevention System(IPS)
> IPS is also considered as an active IDS since it is capable of not only detecting the intrusions but also preventing them

### Classification of IPS
Like IDS, IPS are also classified into two types: 
- Host-based IPS 
- Network-based IPS

### Difference between IDS, IPS 

|      | IPS                                    | IDS                      |
| ---- | -------------------------------------- | ------------------------ |
| 差別 | inline(當有流量進進出出，可以直接阻擋) | 從旁(只能觀測)(吃瓜群眾) |
| 差別 | active(主動)                           | passive                  |

## Firewall
> 封包篩選裝置

### Firewall Architecture
- Bastion Host
    - 防禦主機式架構
- Screened Subnet
    - 一層防火牆，會有瓶頸問題
    - 屏蔽式網路架構
    - DMZ (非戰區)
- Multi-homed Firewall
    - 兩層防火牆
    - 連續式架構 back-to-back
    - 好處：防火牆負擔低
    - 兩片以上網卡都算multi-homed 

### DMZ (Demilitarized Zone)
> The DMZ 
> **serves as a buffer** between the secure internal network and the insecure Internet, as it adds a layer of security to the corporate LAN, thus preventing direct access to other parts of the network.
> 非戰區，在這區打仗不算戰爭(緩衝地帶) 

### Types of Firewalls
1. Hardware Firewall
    - PGA，不需要軟體驅動
2. Software Firewall
    - 主機板上是CPU，需要軟體驅動
- 軟體防火牆 VS 硬體防火牆
    - 軟體防火牆也稱為個人防火牆，它是最常用的防火牆，通常作為計算機系統上的程序運行。
    - 硬體防火牆是指把防火牆程序做到晶片裡面，由硬體執行這些功能，能減少CPU的負擔，使路由更穩定。


## Honeypot
> honeypot 
> is a computer system on the Internet intended to attract and trap those who attempt unauthorized or illicit utilization of the host system to penetrate an organization’s network.
> 誘捕系統
> 放在網路上讓駭客打，藉由分析log看看駭客在幹嘛

### Types of Honeypots
- low-interaction Honeypots
    - 服務很少
- medium-interaction Honeypots
- high-interaction Honeypots
    - ex: linux系統可以感染病毒，也可以感染windows作業系統

## IDS, IPS, Firewall, and Honeypot Solutions
### Intrusion Detection Tools
- **snort**，Source: https://www.snort.org 
    - **入侵偵測系統**
- **OSSEC**，Source: (https://www.ossec.net)
    - **主機型入侵偵測系統**
- baseline 
    - 靠機器學習做基準值，來作為判斷依據
### Intrusion Detection Tools for mobile
- zIPS，Source: https://www.zimperium.com
- Wifi Inspector Source: https://play.google.com
- Wifi Intruder Detect，Source: https://wifi-intruder-detect.en.aptoide.com

### Honeypot Tools
- SPECTER Source: http://www.specter.com

## Evading IDS
### IDS Evasion Techniques 
:::danger
考試會考
:::

> IDS that provide an extra layer of security to the organization’s infrastructure are interesting targets for attackers. Attackers implement various IDS evasion techniques to bypass such security mechanisms and compromise the infrastructure. IDS evasion is the process of modifying attacks to fool the IDS/IPS into interpreting that the traffic is legitimate and thus prevent the IDS from triggering an alert. Many IDS evasion techniques can perform IDS evasion in different and effective ways.

Some IDS evasion techniques are as follows
1. Insertion Attack 
2. Evasion 
3. DoS Attack
4. Obfuscating 
5. False Positive Generation 
6. Session Splicing 
7. Unicode Evasion 
8. Fragmentation Attack
9. Overlapping Fragments
10. Time-To-Live Attacks 
11. Invalid RST Packets 
12. Urgency Flag 
13. Polymorphic Shellcode 
14. ASCII Shellcode 
15. Application-Layer Attacks
16. Desynchronization 
17. Encryption 
18. Flooding
## IDS evasion techniques
### 1. Insertion Attack
### 2. Evasion
### 3. Denial-of-Service Attack
### 4. Obfuscating
> 混淆
- path referenced in the signature
- encode attack patterns in unicode
- polymorphic code
- encrypted protocols
### 5. False Positive Generation
| False Alarm | IDS  | End System |  Attack   |
|:-----------:|:----:|:----------:|:---------:|
|    誤報     |  有  |     沒     | Insertion |
|    漏報     | 沒有 |   **有**   |  Evasion  |
### 6. Sessoin Splicing 
:::danger
出題機率高
:::

- 把攻擊行為拆解到不同封包
### 7. Unicode Evasion
- 攻擊HTTP
### 8. Fragmentation Attack 
- 分片式攻擊
- IP封包被切割
- 透過將惡意程式分割繞過偵測機制，進入系統後再組裝 應該是這樣
### 9. Overlapping Fragments
### 10. Time-To-Live Attacks
- TTL一定會跨過router
- 基於TTL做分片攻擊
- 目標:傳123封包
    - 封包2的TTL設定為1 讓Router drop掉
    - 再補上封包2 組合成123
### 11. Invalid RST Packets1
- attacker send the RST packet to IDS with an invalid checksum
- 入侵偵測的誤報
### 12. urgency flag
- 在flag打開，重組封包會有1 byte 封包遺失
- 改變封包特徵，讓偵測系統漏報
### 13. Polymorphic Shellcode
- 變種後的shellcode
### 14. ACSII Shellcode
### 15. Application-Layer Attacks
### 16. Desychronization
- Pre-Connection SYN
    > 在三項交握前干擾
- Post-Connection SYN
    > 在三項交握後干擾
### 17. Encryption
### 18. Flooding


## Evading Firewalls


## Firewall Evasion Techniques
1. Port Scanning 
2. Firewalking 
3. Banner Grabbing 
4. IP Address Spoofing 
5. Source Routing 
6. Tiny Fragments 
7. Using an IP Address in Place of a URL 
8. Using Anonymous Website Surfing Sites 
9. Using a Proxy Server
10. ICMP Tunneling 
11. ACK Tunneling
12. HTTP Tunneling 
13. SSH Tunneling 
14. DNS Tunneling 
15. Through External Systems 
16. Through MITM Attack 
17. Through Content 
18. Through XSS Attack

### 1. Firewalking
```shell=
sudo nmap scanme.nmap.org -n --traceroute --script=firewalk
```
### 2. Banner Grabbing
### 3. IP Address Spoofing
### 4. Source Routing
### 5. Tiny Fragments
- 有些小封包就不會檢查
### 6. Using IP Address in Place of a URL
- 用IP取代網址
- ipleak.net

### 7. Using a Proxy Server
### 8. ICMP Tunneling
- 封包放在ICMP裡
### 9. ACK Tunneling
- 封包放在ACK封包裡
### 10. HTTP Tunneling
- 封包放在HTTP裡
### 11. SSH and DNS Tunneling
- 封包放在SSH裡
- NSX
### 12. Through External Systems
### 13. Through MITM Attack
### 14. Through Content
### 15. Through XSS Attack

:::info
### 補充-Firewall filter
- 三種：IP, Port, Content
- [IP, Port] => Port Redireciton
    - 偵查: 來源
    - 解決辦法: 重導
    - bypass IP 藉由bypass Port：攻擊方式 Port Redirection
- [Content]  => Encapulation/Tunneling
    - 偵查: 內容
    - 解決辦法: 藏起來
:::


## IDS/Firewall Evading Tools
- Traffic IQ Professional，Source: https://www.idappcom.com
- Nmap (https://nmap.org) 
- Metasploit (https://www.metasploit.com) 
- Inundator (https://sourceforge.net) 
- IDS-Evasion (https://github.com) 
- Hyperion-2.0 (http://nullsecurity.net) 
### Packet Fragment Generator Tools
- Colasoft Packet Builder，Source: https://www.colasoft.com 
- CommView (https://www.tamos.com) 
- NetScanTools Pro (https://www.netscantools.com) 
- Ostinato (https://ostinato.org) 
- WAN Killer (https://www.solarwinds.com) 
- WireEdit (https://wireedit.com)

## Detecting Honeypots
- 如何檢測到誘捕系統的特徵
    - **是不是虛擬機: 虛擬機的網路卡後都是固定的**

### Honeypot Detection Tools 
- Send-Safe Honeypot Hunter (http://www.send-safe.com) 
- kippo_detect (https://github.com) 

## CH12 Practice
1. [Lab 2-1] Bypass Windows Firewall using Nmap Evasion Techniques
