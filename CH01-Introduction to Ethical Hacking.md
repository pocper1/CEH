{%hackmd @themes/notion %}

###### tags: `資訊安全`


# CH01-Introduction to Ethical Hacking
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/01(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章目錄
[TOC]

---

## Security Events
- [2022/05/01 嚴重資安漏洞-Log4j](https://www.ithome.com.tw/news/150656)
    > Java 伺服器紀錄log的漏洞

- [NSO Group用來駭進蘋果iMessage](https://www.ithome.com.tw/news/148401)
    > iphone 只要預覽連結就中毒
    > iphone JBIG2透過 intger overflow 打造軟體CPU
    
## CEH test Info
- Exam Code: 312-50
- 4 hours
- 125 Questions
- 考試當天才會知道，通過分數
- 考試題目都在課本裡

## Information Security Overview
### Elements of Information Security
1. Confidentiality
    > 保密性
    > Confidentiality is the assurance that the information is accessible only to authorized.
2. Integrity
    > 完整性
    > Integrity is the trustworthiness of data or resources in the prevention of improper and unauthorized changes—the assurance that information is sufficiently accurate for its purpose.
3. Availability
    > 可用性
    > Availability is the assurance that the systems responsible for delivering, storing, and processing information are accessible when required by authorized users.
4. Authenticity
    > 真實性
    > Authenticity refers to the characteristic of communication, documents, or any data that ensures the quality of being genuine or uncorrupted.
5. Non-Repudiation
    > 不可否認性
    > Non-repudiation is a way to guarantee that the sender of a message cannot later deny having sent the message and that the recipient cannot deny having received the message.

###  Objectives of Information Security Attacks
> 攻擊成功的四大要素

\begin{aligned}		
	Attack &= Motive(Goal) + Method + Vulnerability \\
    攻擊 &= 動機 + (能力 + 資源) + 機會
\end{aligned}

## Classification of Attacks
> 攻擊種類

1. Passive Attacks
    > 被動攻擊
    - 目的: 監控網路流量(monitoring network traffic) 
    - ex:
        - Footprinting
        - Sniffing and eavesdropping
        - Networks traffic analysis
        - Decrption of weaklu encrypted traffic
2. Active Attacks
    > 主動攻擊
    - 目的: 中斷網路(disrupt the communication) 
    - ex: 
        - DoS attack
        - Bypassing protectino mechanisms
        - Malware attacks (such as viruses worms ransomware)
        - Replay attacks
            - 中間人攻擊的一種(重放監聽到的密碼去獲得伺服器身分認證)
        - Spoofing attacks
        - Modification of infomation
3. Close-in Attacks
    > 近距離攻擊
    - 目的: distupt access
    - 時事: [iphone 偷資料-OMG cable](https://hypebeast.com/zh/2021/9/omg-cables-hacking-usb-c-lightning-cable-info)
    - ex: 
        - Social Engineering(Eavesdropping, shoulder surfing, dumpster diving, and other methods)
4. Insider Attacks
    > 內賊
    - 目的: violate rules
    - ex: 
        - Eavesdropping and wireapping (竊聽)
        - Theft of physical devices
        - Social engineering
        - Data theft and spoliation
        - Pod Slurping
        - Planting keyloggers, backdoors, or malware
5. Distribution Attacks
    > 散播攻擊
    - 目的: tamper with hardware or software(在製造/發行 更改軟/硬體)

## Cyber Kill Chain Concepts
### Cyber Kill Chain Methodology
> The cyber kill chain methodology is a component of intelligence-driven defense for the identification and prevention of malicious intrusion activities. This methodology helps security professionals in identifying the steps that adversaries follow in order to accomplish their goals.

### CKC
> Cyber Kill Chain (CKC) 網路殺傷鏈

1. Reconnalssance 
    > 偵查
    > An adversary performs reconnaissance to collect as much information about the target as possible to probe for weak points before actually attacking.
2. Weaponlzation
    > 武裝
    > The adversary analyzes the data collected in the previous stage to identify the vulnerabilities and techniques that can exploit and gain unauthorized access to the target organization.
3. Delivery
    > 遞送
    > The previous stage included creating a weapon. Its payload is transmitted to the intended victim(s) as an email attachment, via a malicious link on websites, or through a vulnerable web application or USB drive.

4. Explotation
    > 開採
    > After the weapon is transmitted to the intended victim, exploitation triggers the adversary’s malicious code to exploit a vulnerability in the operating system, application, or server on a target system.
5. Installation
    > 安裝
    > The adversary downloads and installs more malicious software on the target system to maintain access to the target network for an extended period.
6. Command and Control
    > 發令與控制
    > The adversary creates a command and control channel, which establishes two-way communication between the victim’s system and adversary-controlled server to communicate and pass data back and forth
7. Action an Objectives
    > 行動
    > The adversary controls the victim’s system from a remote location and finally accomplishes their intended goals.

<img src="https://img2020.cnblogs.com/blog/1073473/202008/1073473-20200827125455160-2135375247.png " style="width:50%; padding-left:25%" />

### TTPs
> TTP: Tactics(戰術)、Techniques(技術)、Procedures beforehand(程序)
> CKC目的: TTP攻擊流程標準化

### Adversary Behaviors Identification
:::danger
考試會考
:::
1. Internal Reconnaissance
2. Use of PowerShell
3. Unspecified Proxy Activities
4. use of Command-Line interface
5. HTTP User Agent
6. Command and Control Server
7. Use of DNS Tunneling
8. Use of Web Shell 
    - Chinese chopper webshell，[Wikipedia-Chinese chopper](https://en.wikipedia.org/wiki/China_Chopper)
    - antsword
9. Data Staging
    - emotet病毒，[資安日報-emotet病毒](https://www.ithome.com.tw/news/149414)
        - 攻擊步驟：word -> VBA -> powershell -> exe.downloader -> twext.exe

### Indicators of Compromise(IoCs)
> 入侵指標，IoCs 分為四類
1. Email Indicators
2. Network Indicators
3. Host Based Indicators
4. Behavioral Indicators

## Hacking Concepts
### what is hacking
> Hacking in the field of computer security refers to exploiting system vulnerabilities and compromising security controls to gain unauthorized or inappropriate access to system resources. It involves a modifying system or application features to achieve a goal outside its creator’s original purpose. Hacking can be done to steal, pilfer, or redistribute intellectual property, thus leading to business loss.

### Hacker Classes 
- Black Hats
    - 黑帽駭客
    - Black hats are individuals who use their extraordinary computing skills for illegal or malicious purposes. This category of hacker is often involved in criminal activities. They are also known as crackers.
- White Hats
    - 白帽駭客
    - White hats or penetration testers are individuals who use their hacking skills for defensive purposes. These days, almost every organization has security analysts who are knowledgeable about hacking countermeasures, which can secure its network and information systems against malicious attacks. They have permission from the system owner.
- Gray Hats
    - 灰帽駭客
    - Gray hats are the individuals who work both offensively and defensively at various times. Gray hats might help hackers to find various vulnerabilities in a system or network and, at the same time, help vendors to improve products (software or hardware) by checking limitations and making them more secure.
- Suicide Hackers
    - 自殺式駭客
    - Suicide hackers are individuals who aim to bring down critical infrastructure for a “cause” and are not worried about facing jail terms or any other kind of punishment. Suicide hackers are similar to suicide bombers who sacrifice their life for an attack and are thus not concerned with the consequences of their actions.
- Script Kiddies
    - 腳本小子
    - cript kiddies are unskilled hackers who compromise systems by running scripts, tools, and software developed by real hackers. They usually focus on the quantity rather than the quality of the attacks that they initiate.
- Cyber Terrorists
    - 網路恐怖主義
    - Cyber terrorists are individuals with a wide range of skills, motivated by religious or political beliefs, to create fear of large-scale disruption of computer networks.
- State-Sponsored Hackers
    - 國家級駭客
    - State-sponsored hackers are individuals employed by the government to penetrate, gain top-secret information from, and damage the information systems of other governments.
- Hacktivist
    - 激進黑客
    - Hacktivism is when hackers break into government or corporate computer systems as an act of protest. Hacktivists use hacking to increase awareness of their social or political agendas, as well as to boost their own reputations in both the online and offline arenas. They are individuals who use hacking to promote a political agenda, especially by defacing or disabling websites. Common hacktivist targets include government agencies, multinational corporations, and any other entity that they perceive as a threat. Irrespective of the hacktivists’ intentions, the gaining of unauthorized access is a crime.

:::info
## 補充資料
### 駭客動機
1. 軍事化
2. 犯罪化
3. 激進主義化
### 駭客組織
1. 敘利亞電子軍
2. kaspersky 
3. NSA TAO(美國特定入侵行動辦公室)
:::

## Ethical Hacking Concepts
### What is Ethical Hacking
> Ethical hacking is the practice of employing computer and network skills in order to assist organizations in testing their network security for possible loopholes and vulnerabilities. 

> 普遍：Penetration Testing
> 現在：道德駭客->領獎金

:::danger
考試會考
- **Bug bounty program**->找到回報hackerone
:::

### Cyber Threat Intelligence
> 網路威脅情資
- threat hunting

### Threat Modeling
> 威脅模型
1. Identify Security Objectives
2. Application Overview
3. Decompose the Application
4. Identify Threats
5. Identify Vulnerablities

- CAPEC 攻擊手法的字典

### IH&R process
> 遭遇資安事件處理辦法
1. Preparation(準備)
2. Incident Recording and Assignment(事件紀錄)
3. Incident Triage(歸類)
4. Notification(通報)
5. Containment(封鎖)
6. Evidence Gathering and Forensic Analysis(蒐集證據以及分析)
7. Eradication(加強防禦)
8. Recovery(恢復)
9. Post-Incident Activities(從經驗當中記取教訓)


## Information Security Laws and Standards
:::danger
考試會考
:::
> 資安相關法規，要知道甚麼法規管甚麼
1. ISO/IEC 27001:2013 
    - 中文名稱: information security management system(資訊管理系統的條件，ISMS)
    - 目的: 好的ISM該有的條件
2. ISO/IEC 27002: code of pratice
    - 中文名稱: 施行細則
    - 目的: 27001的實行手冊
3. HIPAA
    - 中文名稱: 健康保險便利和責任法案
    - 目的: 在管醫療個資
4. Sarbanes Oxley Act
    - 中文名稱: 沙賓法案、SOX法案
    - 目的: 股票上市公司的內積內控(公司治理)
5. DMCA
    - 中文名稱: 數位千喜著作權法案(Digital Millennium Copyright Act，DMCA)
    - 目的: 規定其網站上供人發表貼文/使用者創作內容的線上服務供應商若在收到著作權人或其代理人指稱侵權通知後即時移除不當內容，即可免除著作權侵權責任
6. FISMA
    - 中文名稱: 聯邦資訊安全管理法案
    - 目的: 保護美國政府，避免遭受網路安全攻擊和自然災害，致使敏感資料遭遇風險
7. Payment Card Industry Data Security Standard(PCI DSS)
    - 中文名稱: 支付卡產業資料安全標準(Payment Card Industry Data Security Standard，簡稱 PCI DSS)
    - 目的: 支付卡產業安全標準協會所制定的標準，是基於保障持卡人資料安全的全球統一規範；這項法規規範了 payment card data security
8. Data Protestion Act 2018 (DPA)
    - 中文名稱: 一般資料保護規則，General Data Protection Regulation，縮寫GDPR
    - 目的: 歐盟法律中對所有歐盟個人和隱私的規範，涉及了歐洲境外的個人資料出口。GDPR 主要目標為取回個人對於個人資料的控制，以及為了國際商務而簡化在歐盟內的統一規範。
