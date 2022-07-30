{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH16-Hacking Wireless Networks
| 事項         | 時間                              |
| ------------ | --------------------------------- |
| 上課日期     | 2022/06/25(六) 09:00 ~ 18:00      |
| 最後更新日期 | 2022/07/31(日) 01:35              |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 了解無線網路加密種類
> 了解無線網路的攻擊方式
---

## Wireless Concepts
> Network technology is heading toward a new era of technological evolution through wireless technologies. Wireless networking is revolutionizing the way people work and play. By removing physical connections or cables, individuals can use networks in new ways to make data portable, mobile, and accessible. A wireless network is an unbounded data communication system that uses radio-frequency technology to communicate with devices and obtain data. This network frees the user from complicated and multiple wired connections using electromagnetic (EM) waves to interconnect two individual points without establishing any physical connection. This section will describe basic wireless concepts.

<!-- - lifi-光照上網技術 -->
## Wireless Networks
- wireless networks- based on IEEE 802.11 stardard
    - wifi 802.11
    - bluetooth 802.15.11
        - BLE：低功耗藍芽
        - NFC：比ble更低耗
    - zigbee 802.15.4
    - WiMax 802.16

### SSID/BSSID (Service Set Identified)
- SSID / ESSID(extension SSID)
    - 無線網路服務代號
- BSSID
    - 每個基地台自己代號
![來自: https://ppt.cc/fXIvex](https://i.imgur.com/mfs67Cp.png)

### Shared key v.s. Preshared key
- shared key
- WPA/WAP2/WPA3-Personal -> Preshared Key

### 802.1x
- EAP (Extensible Authentication Protocol)
> EAP-requset, port based network access control

![可擴展身份驗證協議 EAP](https://mrncciew.files.wordpress.com/2013/03/wlan-eap1.png?w=529&h=342)

### Type of Wireless Antennas
> 天線種類
- directional Antennas(指向性天線)
- omnidirectional Antennas(全向性天線)
- Parabolic Grid Antennas(拋物面天線)
- Yagi Antennas(八木天線)
- Dipole Antennas(偶極子天線)
- Reflector Antennas(反射器天線)

## Wireless Encryption
### WEP 
![](https://i.imgur.com/rxVjev3.png =80%x)
> WEP is an encryption algorithm for IEEE 802.11 wireless networks. It is an old wireless security standard and can be cracked easily.
- RC4 cipher
- 已被破解
### WPA
> It is an advanced wireless encryption protocol using TKIP and Message Integrity Check (MIC) to provide strong encryption and authentication. It uses a 48-bit initialization vector (IV), 32-bit cyclic redundancy check (CRC), and TKIP encryption for wireless security.
- WEP加強版
- 已被破解
### WPA2
![](https://i.imgur.com/xpSpeNn.png =70%x)
> It is an upgrade to WPA using AES and the Counter Mode Cipher Block Chaining Message Authentication Code Protocol (CCMP) for wireless data encryption.
- AES-based encryption
- CCMP based
- MITM and DoS attacks

### WPA3
> It is a third-generation Wi-Fi security protocol that provides new features for personal and enterprise usage. It uses Galois/Counter Mode-256 (GCMP-256) for encryption and the 384-bit hash message authentication code with the Secure Hash Algorithm (HMAC-SHA-384) for authentication.
- vulnerablity: drangonblood
- GCMP-256 encryption 
- HMAC-SHA-384 alogrithm
- 不是IEEE標準

#### Modes of Operations
- WPA3-Personal
    - password-based authentication
    -  it uses a modern key establishment protocol called the Simultaneous Authentication of Equals (SAE)
    -  features
        - Resistance to offline dictionary attacks
        - Resistance to key recovery
        - Natural password choice
        - Easy accessibility
- **WPA3-Enterprise**
    :::danger
    考試會考
    :::
    - protects sensitive data
    - **GCMP-256(金鑰加密)**
    - **HMAC-SHA-384(金鑰產生)**
    - **ECDSA-384(金鑰交換)**

### Comparsion of WEP, WPA, WPA2, WPA3
![](https://i.imgur.com/CVQv1ed.png)
## Wire Threats
1. Confidentiality Attack
    - Eavesdropping
    - Traffic Analysis
    - Cracking WEP Key 
    - **Evil Twin AP**
    - Honeypot AP
    - Session Hijacking
    - Masquerading
    - MITM Attack
2. Availability Attacks
    - Access Point Theft
    - Disassociation Attacks
    - EAP-Failure 
    - Beacon Flood
    - **Denial-of-Service**
    - De-authenticate Flood
    - Routing Attacks
    - Authenticate Flood
    - Address Resolution Protocol (ARP) Cache Poisoning Attacks
    - Power Saving Attacks
    - TKIP MIC Exploit
3. Authentication Attacks
    - PSK Cracking 
    - LEAP Cracking
    - VPN Login Cracking
    - Domain Login Cracking
    - Key Reinstallation Attack
    - Identity Theft 
    - Shared Key Guessing
    - Password Speculation
    - Application Login Theft
### Rogue AP Attack
> 流氓接入點
> ex: 自己架的wifi

> In order to create a backdoor to a trusted network, an attacker may install an unsecured AP or fake AP inside a firewall. The attacker may also use software or hardware APs to perform this kind of attack. A wireless AP is termed a rogue access point when it is installed on a trusted network without authorization. An inside or outside attacker can install rogue APs on a trusted network with malicious intentions.


<img src="https://www.researchgate.net/publication/327264581/figure/fig1/AS:664585870786560@1535461027087/Attack-model-of-rogue-APs.png" alt="Attack model of rogue APs." style="width:60%; padding-left:20%"/>

### Unauthorized Association
- hack 到受害端，從受害端分享 wifi 讓 attacker 進入內網

### Ad-Hoc Connection Attack
- Ad hoc 是一個拉丁文常用短語。這個短語的意思是「特設的、特定目的的、即席的、臨時的、將就的、專案的」
- 隨意網路攻擊

### AP MAC Spoofing
- 假造卡號攻擊
- 透過假造卡號騙過內網的偵查機制

### Denial of Service Attack
- 阻斷式網路攻擊

 
### Key Reinstallation Attack(KRACK)
:::danger
考試會考
:::
![](https://i.imgur.com/zvWlQWf.png)
![](https://i.imgur.com/eyUsJfl.png)
> The key reinstallation attack (KRACK) exploits the flaws in the implementation of the four-way handshake process in the WPA2 authentication protocol, which is used to establish a connection between a device and an AP. All secure Wi-Fi networks use the four-way handshake process to establish connections and to generate a fresh encryption key that will be used to encrypt the network traffic.
- 利用四向交握 固定nounce，讓加密的方式可預測
- 針對WPA2 protocol

 
### aLTEr Attack
:::danger
考試會考
:::
> 一個4G協議漏洞，對於LTE網絡，也可以達到與WIFI釣魚攻擊類似的攻擊效果
- 假造 4G 基地台
- Long-Term Evolution (LTE)
- aLTEr attacks are usually performed on LTE devices

### Wormhole and Sinkhole Attacks 
#### Wormhole Attacks
> 蟲洞攻擊
> ex: 手機惡意程式種後門，attacker 傳釣魚網站到target
- creates a tunnel vpn (傳送門)
- locates himself strategically i the target network
- exploits dynamic routing protocols

<img src="https://www.researchgate.net/profile/Farrukh_Khan5/publication/282500613/figure/fig1/AS:652953174147083@1532687576252/Working-of-Wormhole-Attack-in-MANETs.png" style="width:70%; padding-left:15%" />

#### Sinkhole Attacks
> (天坑、陷阱)(水坑攻擊)
- ex: 埋伏
- uses a malicious node and advertises the node
- places the malicious node the base station 
<img src="https://d3i71xaburhd42.cloudfront.net/cae32d702c99a16b2cb1e5a2fa696910504250a3/3-Figure1-1.png"  style="width:70%; padding-left:15%" />

## Wi-Fi Discovery
### Wireless Network Footprinting
> 無線網路找尋
1. Wifi Discovery: Wireless Network Footprinting
    - passive Footprinting Method
        - detect the existence of an AP
    - active Footprinting Method
        - sends out a probe request with the SSID

### launch of wireless attacks
> 發起無線網路攻擊方式

#### aircrack-ng suite
| 常見           | 不常見          |
|:-------------- |:--------------- |
| 1. Airmon-ng   | 6. Airdecap     |
| 2. Airodump-ng | 7. Airdeclock   |
| 3. Airplay-ng  | 8. Airgragh     |
| 4. Aircrack-ng | 9. Airolib      |
| 5. Airbase-ng  | 10. Airserv     |
|                | 11. Airtuun     |
|                | 12. Easside     |
|                | 13. Packetfoxge |
|                | 14. Tkiptun     |
|                | 15. Wesside     |
|                | 16. WZCook      |


### Denial-of-Services: Disassociation and De-authentication Attacks

### Man-in-the-Middle Attack
- 準備好一樣的卡號和SSID 
- 讓AP的使用者斷線，因斷線後wifi會自動重新連線，這時hacker假造MAC address ，導入到指定位置
<img src="https://threatcop.com/blog/wp-content/uploads/2019/10/CISO-Mag.webp" alt="(Source: CISO Mag)" style="width:70%; padding-left:15%" />

### Evil Twin
> 邪惡雙胞胎
> An evil twin is a wireless AP that pretends to be a legitimate AP by imitating its SSID. It poses a clear and present danger to wireless users on private and public WLANs. 
- 把自己的電腦模擬成軟體基地台
<img src="https://www.researchgate.net/profile/Omar-Nakhila/publication/321122614/figure/fig5/AS:631949064421377@1527679806852/Illustration-of-an-Evil-Twin-Attack-The-attacker-can-successfully-lure-a-victim-into.png" style="width:70%; padding-left:15%" />

### aLTEr Attack
An aLTEr attack has the following two phases.
- Information gathering phase: Attackers passively gather information needed to perform an aLTEr attack using techniques such as identity mapping and website fingerprinting.
- Attack phase: Attackers use the information gathered to perform an active attack using techniques such as DNS spoofing

<img src="https://images.idgesg.net/images/article/2018/07/alter_mitmattack-100763554-large.jpg?auto=webp&quality=85,70" />

### dns snoofing
- 先斷線，使用者在聯的時候再側錄封包

## Wifi Encrpytion Cracking
### WPA3 Encrytpion Cracking

#### Dragonblood
- vulnerabilities in the WPA3 實作攻擊(程式沒有寫好)
    - dragonblood is a set of vulnerable in the WPA3

## Bluetooth Hacking
### bluetooth attacks
1. btlejacking
    >  A Btlejacking attack is detrimental to Bluetooth low energy (BLE) devices. The attacker can sniff, jam, and take control of the data transmission between BLE devices by performing an MITM attack. 
    - 藍芽列表
    - 藍芽的MITM
2. KNOB attack
    >  A Key Negotiation of Bluetooth (KNOB) attack enables an attacker to breach Bluetooth security mechanisms and perform am MITM attack on paired devices without being traced. The attacker leverages a vulnerability in the Bluetooth wireless standard and eavesdrops on all the data being shared in the network, such as keystrokes, chats, and documents.
    -  藍芽密鑰協商攻擊 (MITM)

#### Bluejacking
> Bluejacking is a method of temporarily hijacking a smartphone by sending it an anonymous text message using the Bluetooth wireless networking system.
- 匿名藍芽攻擊，設定可被探索





