{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH17-Hacking Mobile Platforms
| 事項         | 時間                              |
| ------------ | --------------------------------- |
| 上課日期     | 2022/06/25(六) 09:00 ~ 18:00      |
| 最後更新日期 | 2022/07/31(日) 01:35              |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 了解手機平台的攻擊向量
> 了解如何破解Android OS和iOS 系統
---

## Mobile Platform Attack Vectors
### OWASP 10 mobile risks 2016
- M1-Improper platform usage
- M2-Insecure data storage
- M3-Insecure communication
- M4-Insecure authecation
- M5-Insufficient cryptography
- M6-Insecure authorization
- M7-Client code quality
- M8-Code tampering
- M9-Reverse engineering
- M10-Extraneous functionality

### Anatomy of a Mobile Attack
- The Device
    - Browser-based Attacks
        - Phishing
        - Framing
        - Clickjacking
        - Man-in-the-Mobile
        - Buffer Overflow
        - Data Caching
    - Phone/SMS-based Attacks
        - Baseband Attacks
        - SmiShing
    - Application-based Attacks
        - Sensitive Data Storage
        - No Encryption/Weak Encryption
        - Improper SSL Validation
        - Configuration Manipulation
        - Dynamic Runtime Injection
        - Unintended Permissions
        - Escalated Privleges
    - The System
        - No Passcode/Weak Passcode
        - iOS Jailbreaking
        - Android Rooting
        - OS Data Caching
        - Passwords and Data Accessible
        - Carrier-loaded Software
        - User-initiated Code
    - The Network
        - Wi-Fi(weak encrption/no encrption)
        - Rogue Access Points
        - Packet Sniffing
        - Man-in-the-Middle(MITM)
        - Session Hijacking
        - DNS Poisoning
        - SSLStrip
        - Fake SSL Certificates
    - The Data Center/CLOUD
        - Web-server-based attacks
        - Platform Vulnerabilities
        - Server Misconfiguration
        - Cross-site Scripting (XSS)
        - Cross-Site Request Forgery (CSRF)
        - Weak Input Validation
        - Brute-Force Attacks
    - Database Attacks Database-based vulnerabilities and attacks are of the following types:
        - SQL injection
        - Privilege Escalation
        - Data Dumping
        - OS Command Execution

### App Sandboxing Issues
- protect system

### SMS phishing

### Agent Smith Attack
> 它專門利用作業系統的漏洞來感染 Android 裝置，暗中將已安裝的應用程式替換成惡意版本。根據研究人員指出，此惡意程式會在受害手機上顯示詐騙廣告，但它其實還可能發動其他更危險的攻擊，如：竊取銀行資訊或監控使用者。

### Exploiting SS7 Vulnerability
### SIM Card Attack

## Android

- 底層架構: Linux
- dirty pipe

### Android Rooting

### Network cutting
### Main-in-the-Disk Attack
:::danger
考試會考
:::

### Spearphone Attack
:::danger
考試會考
:::
> 側錄免持聽筒
### Netcut
> 使別人斷網

## Hacking iOS
### Jailbreaking iOS
- 有一家公司unc0ver
    - 破解了 ios 11.0~14.0
### 4 type jailbreaking
> 四種 iOS 越獄
- untethered jailbreaking
    - (完美jb)
    - 重開機後一樣是越獄後
- Semi-tethered Jailbreaking
- tethered jailbreaking
    - (不完美jb)
    - 重開機後就沒了
- Semi-unthered Jailbreaking

### IOS Trustjacking
> capture sensitive information
- iTunes Wi-Fi Sync

### IOS Hacking Tools
- ElcomsoftPhone Breaker
- [iphone power off track](https://www.google.com/search?q=iphone+power+off+track&rlz=1C1CHBF_zh-TWTW913TW913&oq=iphone+power+off+track&aqs=chrome..69i57j0i512j0i8i10i30j0i8i30.6491j0j1&sourceid=chrome&ie=UTF-8)
    > 手機的隱私問題比安全問題重要
    > Iphone 11以上斷電後仍然可被追蹤

