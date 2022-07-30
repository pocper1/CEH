{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH18-IOT and OT Hacking
| 事項         | 時間                              |
| ------------ | --------------------------------- |
| 上課日期     | 2022/06/25(六) 09:00 ~ 18:00      |
| 最後更新日期 | 2022/07/31(日) 01:35              |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 了解什麼是IoT和OT，以及應對攻擊方式
---

> IOT definition：傳統存在的東西加是網路功能
## IoT Hacking
### IOT Communication Models
1. Device-To-Device Model
    <img src="https://www.researchgate.net/profile/Juliet-Odii/publication/334603508/figure/fig1/AS:783353557028866@1563777450862/Example-of-device-to-device-communication-model.jpg" />
2. Device-To-Cloud Model
    <img src="https://www.researchgate.net/profile/Juliet-Odii/publication/334603508/figure/fig2/AS:783353557041153@1563777450885/Device-to-cloud-communication-model-diagram.jpg" />

3. Device-to-Gateway Model
    <img src="https://www.researchgate.net/profile/Juliet-Odii/publication/334603508/figure/fig3/AS:783353557045250@1563777450909/Device-to-gateway-communication-model-diagram.jpg" />
4. Back-End Data-Sharing Model
    <img src="https://www.researchgate.net/profile/Juliet-Odii/publication/334603508/figure/fig4/AS:783353557041154@1563777450936/Back-end-data-sharing-model-diagram.jpg" />
    
### Challenges of IoT
- Lack of security and privacy
    - [Amazon Echo捲入謀殺命案中，而且可能成為唯一「證人」？](https://www.bnext.com.tw/article/42556/an-amazon-echo-may-be-the-key-to-solving-a-murder-case)


### Threat vs Opportunity
- MISCONFIGURED and MISAPPREHENDED, the IoT poses an unprecedented risk to personal data, privacy, and safety. 
- If APPREHENDED and PROTECTED, IoT can boost transmissions, communications, delivery of services, and standard of living. 

## IoT Attack
### OWASP Top 10 IoT Threats
1. Weak, Guessable, or Hardcoded Passwords弱密碼、可猜測密碼或裝置預設密碼)
2. Insecure Network Services(不安全的網路服務)
3. Insecure Ecosystem Interfaces(不安全的環境設定介面)
4. Lack of Secure Update Mechanism(缺乏安全的更新機制)
5. Use of Insecure or Outdated(使用不安全或已遭棄用的組件)
6. Insufficient Privacy Protection(不充分的隱私保護)
7. Insecure Data Transfer and Storage(不安全的資料傳輸和儲存)
8. Lack of Device Management(缺乏設備管理)
9. Insecure Default Settings(不安全的預設設定)
10. Lack of Physical Hardening(缺乏實體安全強化)

### Exploit HVAC
> Internet-connected heating, ventilation and air conditioning(HVAC)
- hack corporate systems
- security vulnerabilities

### Rolling code attack
- Rolling code 動態密碼
- An attacker jams and sniffs the signal to obtain the code transferred to a vehicle’s receiver; the attacker then uses it to unlock and steal the vehicle.

### BlueBorne Attack
:::danger
考試會考
:::

- [BlueBorne藍芽漏洞,恐讓數十億裝置暴露於遠端挾持風險 ](https://blog.trendmicro.com.tw/?p=52779)
    >「BlueBorne」是一群由 IoT 資安廠商 Armis 所命名的藍牙漏洞。
    >根據該廠商所提供的詳盡說明，這群存在於藍牙實作上的漏洞遍及各種平台，包括：Android、Linux、iOS 以及 Windows。駭客一旦攻擊成功，就能從遠端挾持裝置。除此之外，駭客還有辦法從一個藍牙裝置跳到另一個藍牙裝置。BlueBorne 漏洞可讓駭客執行惡意程式碼、竊取資料以及發動中間人 (MitM) 攻擊。
### Jamming attack
- 干擾式攻擊
### SDR-Based Attack on IoT
- SDR (software define radio)
> Using a software-based radio communication system, an attacker can examine the communication signals passing through the IoT network and can send spam messages to the interconnected devices.


### Fault injection attack
- 針對硬體的攻擊
>  A fault injection attack occurs when an attacker tries to introduce fault behavior in an IoT device, with the goal of exploiting these faults to compromise the security of that device.

#### Dyn attack
- [2016年Dyn網路攻擊](https://zh.wikipedia.org/zh-tw/2016%E5%B9%B4Dyn%E7%BD%91%E7%BB%9C%E6%94%BB%E5%87%BB)
> Dyn公司和其他DNS提供商提供域名到對應IP位址之間的轉換服務
    這場DDoS攻擊通過惡意操控數以百萬計的IP位址來大量要求域名伺服器進行DNS解析。
    網路安全員相信這場攻擊涉及到由眾多物聯網裝置（包括印表機、網路監控攝影機、家庭路由器和嬰兒監視器）組成的一個殭屍網路，這些裝置均已感染了Mirai惡意軟體。
    這場攻擊估計有1.2Tbps的流量，是迄今為止規模最大的網路攻擊。

### IOT Hacking Methology
#### 攻擊步驟 
The following are the different phases in hacking an IoT device: 
1. Information Gathering 
2. Vulnerability Scanning 
3. Launch Attacks 
4. Gain Remote Access 
5. Maintain Access

#### 攻擊工具
- 掃描工具：**Shodan**
- FCC ID Search
    - 美國通訊協會發的
- RFCrack->rolling code 攻擊
- HackRF One->BlueBorne Attack
    - communication using RF or Zigbee or LoRa

- SDR-Based Attacks using RTL-SDR and GNU Radio
- Firmware-anlyzer

### Solution (how to defend against attack)
- IOT Security Tools
    - **SeaCatio**

## OT Hacking 
### What is OT
> OT is a combination of software and hardware designed to detect or cause changes in industrial operations through direct monitoring and/or controlling of industrial physical devices. 
> Operational technology(OT)->工控
 
|    IT     |            OT            |
|:---------:|:------------------------:|
|    MIS    |           ICS            |
| Dashboard |          SCADA           |
|    x86    | (controller) RTU DCS PLC |
- ICS Industrial Control System 工業控制系統
- SCADA supervisory control and data acquisition 資料採集與監視系統
- RTU Remote Terminal units 遠程終端單元
- DCS Distributed control system 集散控制系統
- PLC Programmable logic controller
### Purdue Model
![](https://i.imgur.com/WY7F3Y8.png =70%x)

### Components of an ICS
- Safety Instrumented System (SIS)
    - 故障保險機制，發生問題系統可以中斷

## OT Attacks
1. HMI-based Attack
2. Side-Channel Attacks
    - 旁道攻擊
    - 基於 時間資訊、功率消耗、電磁泄露或甚是聲音可以提供額外的資訊來源，這可被利用於對系統的進一步破解。
3. Hacking Programmable Logic Controller(PLC)
4. Hacking Industrial Systems through RF Remote Controllers
5. OT Malware


## Information Gathering
### Scanning ICS/SCADA Systems using Nmap
:::danger
考試考參數
:::
![](https://i.imgur.com/IERRlf5.png)
:::info
### 考試重點
1. Siemens SIMATIC 
    - 102
2. Modbus Device
    - 502
3. BACnet Devices
    - 47808
4. Ethernet\IP device
    - 44818
:::

1. Identifying Open Ports and Services 
    ```shell=
    nmap -Pn -sT --scan-delay 1s --max-parallelism 1 -p 80, 102, 443, 502, 530, 593, 789, 1089-1091, 1911, 1962, 2222, 2404, 4000, 4840, 4843, 4911, 9600, 19999, 20000, 20547, 34962-34964, 34980, 44818, 46823, 46824, 55000-55003 <Target IP>
    ```
2. Identifying HMI Systems
    ```shell=
    nmap -Pn -sT -p 46824 <Target IP>
    ```
3. Scanning Siemens SIMATIC S7 PLCs 
    ```shell=
    nmap -Pn -sT -p 102 --script s7-info <Target IP>
    ```
4. Scanning **Modbus** Devices 
    ```shell=
    nmap -Pn -sT -p 502 --script modbus-discover <Target IP>
    ```
    ```shell=
    nmap -sT -Pn -p 502 --script modbus-discover --script-args='modbus-discover.aggressive=true' <Target IP>
    ```
5. Scanning BACnet Devices 
    ```shell=
    nmap -Pn -sU -p 47808 --script bacnet-info <Target IP>
    ```
6. Scanning Ethernet/IP Devices 
    ```shell=
    nmap -Pn -sU -p 44818 --script enip-info <Target IP>
    ```
7. Scanning Niagara Fox Devices 
    ```shell=
    nmap -Pn -sT -p 1911,4911 --script fox-info <Target IP>
    ```

    ```shell=
    nmap -Pn -sT -p 20547 --script proconos-info <Target IP>
    ```
8. Scanning Omron PLC Devices 
    ```shell=
    nmap -Pn -sT -p 9600 --script omron-info <Target IP>
    ```
    ```shell=
     nmap -Pn -sU -p 9600 --script omron-info <Target IP>
    ```
9. Scanning PCWorx Devices 
    ```shell=
     nmap -Pn -sT -p 1962 --script pcworx-info <Target IP> 
    ```

### OT Security Tools
- 工控工具：Flowmon
