{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH6-System Hacking
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/15(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 目的：系統攻擊方式與手法

---
## System Hacking Concepts
1. Footprinting Module(CH02): 
    :::spoiler definition
     > Footprinting is the process of accumulating data about a specific network environment. In the footprinting phase, the attacker creates a profile of the target organization and obtains information such as its IP address range, namespace, and employees. 

    > Footprinting facilitates the process of system hacking by revealing its vulnerabilities. For example, the organization’s website may provide employee bios or a personnel directory, which the hacker can use for social engineering purposes. Conducting a Whois query on the web can provide information about the associated networks and domain names related to a specific organization.
    :::
   
2. Scanning Module(CH03)
    :::spoiler definition
    > Scanning is a procedure used for identifying active hosts, open ports, and unnecessary services enabled on particular hosts. Attackers use different types of scanning methods for host discovery, port and service discovery, operating system (OS) discovery, and evading endpoint security devices such as intrusion detection systems (IDSs) and firewalls. These techniques help attackers identify possible vulnerabilities. Scanning procedures such as port scanning and ping sweeps return information about the services offered by the live hosts that are active on the Internet, and their IP addresses.
    :::
    

3. Enumeration Module(CH04)
    :::spoiler definition
     > Enumeration is a method of intrusive probing, through which attackers gather information such as network user lists, routing tables, security flaws, and Simple Network Management Protocol (SNMP) data. This is of significance, because the attacker ranges over the target territory to glean information about the network, and shared users, groups, applications, and banners.
    
    > Enumeration involves making active connections to the target system or subjecting it to direct queries. Normally, an alert and secure system logs such attempts. Often, the information gathered, such as a DNS address, is publicly available; however, it is possible that the attacker might stumble upon a remote IPC share, such as IPC$ in Windows, that can be probed with a null session, thereby allowing shares and accounts to be enumerated.
    :::
   

4. Vulnerability Analysis Module(CH05)
    :::spoiler definition
     > Vulnerability assessment is an examination of the ability of a system or application, including its current security procedures and controls, to withstand assault. It recognizes, measures, and classifies security vulnerabilities in a computer system, network, and communication channels. 

    > Attackers perform vulnerability analysis to identify security loopholes in the target organization’s network, communication infrastructure, and end systems. The identified vulnerabilities are used by the attackers to perform further exploitation on that target network.
    :::
   
### CEH Hacking Methodolgy(CHM)
- There are four steps in the CHM:
    1. Gaining Access
    2. Escalating Privileges(提權)
    3. Maintaining Access
    4. Clearing Logs
- System Hacking Goals

    | Hacking-Stage     | Goal                                                        | Technique/Exploit Used                                             |
    |:----------------- |:----------------------------------------------------------- |:------------------------------------------------------------------ |
    | 1. Gaining Access | To bypass access controls to gain access to the system      | Passweord cracking, vulnerability exploitation, social engineering |
    | 2. Escalating Privileges | To acquire the rights of another user or an admin           | Exploiting known system vulnerabilities                            |
    | 3. Executing Applications | To create and maintain remote access to the system          | Trojans, spywares,backdoors,keyloggers                             |
    | 4. Hiding Files | To hide attackers' mallicious activities, and to steal data | Rootkits,steganography                                             |
    | 5. Covering Tracks | To hide the evidence of compromise                          | clearing logs                                                      |


![](https://i.imgur.com/aRwIeJx.jpg)

## LAB
> 目的: 查看 Windows 密碼
### Windows SAM
1. windows 密碼表SAM(帳號資料庫)存放路徑
    ```text=
    c:/windows/system32/config/SAM
    ```
2. 透過Registry Editor
    - 看windows 密碼
3. 作業系統
    - Windows        ->administor
    ![](https://i.imgur.com/r4UaTLt.png)
    - Unix 最高權限    ->root

- EX:人民(Administor)是國家的主人但買不到快篩，System(國家機器)

### Use Pstools to privilege escalation
> 有權限看到帳號資料庫
> 舉例：變成國家機器的工具-打不贏就加入

- 使用工具：Pstools->[Pstools 下載位置](https://docs.microsoft.com/zh-tw/sysinternals/downloads/pstools)
- 使用方式
    ```shell=
    ./PsTools/psExec.exe -s -i cmd.exe
    ```
- 目的
    - 這樣就可以從Registry Editor看到對應使用者底下資料(提權)
    ![](https://i.imgur.com/a0ZzZZ5.png)


### How Hash Passwords Are Stored in Windows SAM?
1. NTLM Authentication Process(使用者驗證)
- 有加網域
    > In NTLM authentication, the client and server negotiate an authentication protocol. This is accomplished through the Microsoft-negotiated Security Support Provider (SSP).

2. Kerberos Authentication
- 沒加網域
    > Kerberos is a network authentication protocol that provides strong authentication for client/server applications through secret-key cryptography, which provides mutual authentication. 

## Password Cracking
:::danger
考試必考(會考*13)
:::
### Types of Password Attacks
1. Non-Electronic Attacks
    > 非電子式攻擊
2. Active Online Attacks
    > 線上主動攻擊
3. Passive Online Attacks
    > 線上被動攻擊
4. Offline Attacks
    > 離線攻擊

## Four types of Password Attacks
### 1. Non-Electronic Attacks
1. Social Engineering
    > 社教工程學
2. Shoulder Surfing
    > 窺視
    :::danger
    考試重點------(1)
    :::
3. Dumpster Diving
    > 翻垃圾桶找資料


### 2. Active Online Attacks
1. Dicitionary Attack
    > 字典攻擊
2. Brute Forcing Attack
    > 暴力破解
    - 密碼的可能性
        1. a-z 26個
        2. A-Z: 26個
        3. 0-9 10個
        4. symbol: 32個符號``
        5. space: 1
    
    95 ^ 8 種排列組合 (8個字元的密碼，每個字元有95種可能)
3. Rule-Based Attack
    > 規則攻擊
    :::danger
    考試重點------(2)
    :::
    - ex: keyboard walk (刷鍵盤)[刷鍵盤](https://github.com/hashcat/kwprocessor)
    - 預設密碼清單
    - [Github - 全世界駭客攻擊語法](https://github.com/danielmiessler/SecLists)



4. Hack Injection/Pass-the-Hash (PtH) Attack
    :::danger
    考試重點------(3)
    :::
    1. Hack Injection
        - 從作業系統底層把雜湊撈出來破解
        - 破解工具：[windows l0phtcrack](https://l0phtcrack.gitlab.io/)
        ![](https://i.imgur.com/SHXaRiZ.png)
    2. Pass-the-Hash (PtH) Attack
        > 傳遞雜湊攻擊
        > 直接輸入hash值也可以過身分驗證
        
        

5. LLMNR/NBT-NS Poisoning
    > 用來尋找其他主機的技術，攻擊辦法:截胡
    :::danger
    考試重點------(4)
    :::
    
    :::info
    #### Steps involved in LLMNR/NBT-NS poisoning
    1. The user sends a request to connect to the data-sharing system, \\DataServer, which she mistakenly typed as \\DtaServr.
    2. The \\DataServer responds to the user, saying that it does not know the host named \\DtaServr.
    3. The user then performs a LLMNR/NBT-NS broadcast to find out if anyone in the network knows the host name\\DtaServr.
    4. The attacker replies to the user saying that it is \\DataServer, accepts the user NTLMv2 hash, and responds to the user with an error. 
    :::
    <!--- NTLMv2 hash -->
    - LLMNR/NBT-NS Poisoning Tools
        - 破解工具：Responder
            ```shell=
            sudo responder -I etho
            ```   
        - 原本沒有這個主機，打上面的指令後可以釣魚
            ![](https://i.imgur.com/ct70REt.jpg)
        - 偷到的密碼位置
            ![](https://i.imgur.com/AML3yWk.png)
        - 破解密碼
            ![](https://i.imgur.com/ct70REt.jpg)
            
            ![](https://i.imgur.com/X3BLVhG.png)

6. Trojan/Spyware/Keyloggers
    :::danger
    考試重點------(5)
    :::

7. Password Guessing
    > 密碼猜測->使用預設密碼
    :::danger
    考試重點------(6)
    :::
    
8. Internal Monologue Attack
    > 內心獨白攻擊
    > 在本機透過密碼弄到雜湊
    :::danger
    考試重點------(7)
    :::
    :::info
    #### Steps to perform an internal monologue attack: 
    1. The attacker disables the security controls of NetNTLMv1 by modifying the values of LMCompatibilityLevel, NTLMMinClientSec, and RestrictSendingNTLMTraffic.
    2. The attacker extracts all the non-network logon tokens from all the active processes to masquerade as legitimate users.
    3. Now, the attacker interacts with NTLM SSP locally, for each masqueraded user to obtain a NetNTLMv1 response to the chosen challenge in the security context of that user.
    4. Now, the attacker restores LMCompatibilityLevel, NTLMMinClientSec, and RestrictSendingNTLMTraffic to their actual values.
    5. The attacker uses rainbow tables to crack the NTLM hash of the captured responses. 
    6. Finally, the attacker uses the cracked hashes to gain system-level access.
    :::
   

9. Cracking Kerberos Passwords
    > 三種攻擊kerberos協議
    > 1. AS-REP Roasting技術
    > 2. Kerberoasting(火烤地獄犬攻擊)
    > 3. Pass-the-Ticket Attack(傳遞票券攻擊)
    
    > 攻擊手法：
    > 攻擊者去跟DC(網域工作站)假裝請求做身分認證，然後同時間錄下認證身分的封包，再去破解那個封包
    > 過程：AS ->TGS->AP
    
    1. AS-REP Roasting
        > Cracking TGT
        > 這是一種針對kerberos協議的攻擊技術，不需要認證就可以獲取到使用者的密碼hash值。如果使用者開啟了“不使用Kerberos預認證”，攻擊者就可以獲取到Kerberos AS-REP，經過使用者的RC4-HMAC密碼加密過的，然後他就可以離線破解這個憑證了。
        
        <img src="https://2761223348-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MdS6Wp-xQVaHk-LWQlD%2F-MgbmYDd7oIDpq57IGXN%2F-MgbnEpuGWipYsbQRdUb%2Fimage.png?alt=media&token=c5f68322-67b0-4909-a01f-e15fd441de07"/>
    
    2. Kerberoasting(火烤地獄犬攻擊)
        > Cracking TGS
        - 工具：[Github - Rebeus](https://github.com/GhostPack/Rubeus)
        
        <img src="https://i.imgur.com/4GkCyj7.png" />
   
    3. Pass-the-Ticket Attack(傳遞票券攻擊)
        > 直接拿票券(服務存取的證明)來用
        - 工具：[迷米卡茲(Mimikatz)](https://github.com/gentilkiwi/mimikatz)

    :::danger
    考試重點------(8)
    :::
    :::info
    #### 如果你覺得這三種攻擊方式理解起來容易混淆，那我這裡就以一種簡單的方式來解釋一下
    - AS-REP Roasting：獲取使用者hash然後離線暴力破解
    - Kerberoasting：獲取應用服務hash然後暴力破解
    - Pass-the-Ticket Attack：通過假冒域中不存在的使用者來訪問應用服務
    :::
 
    
### 3. Passive Online Attacks
1. Wire Sniffing
    > 網路監聽
    :::danger
    考試重點------(9)
    :::

2. Man-in-the-Middle Attack
    > 中間人攻擊
    > 中間人(攔截)
    :::danger
    考試重點------(10)
    :::
    
3. Replay Attack
    > 重送攻擊
    :::danger
    考試重點------(11)
    :::

### 4. Offline Attacks
1. Rainbow Table Attack 
    > 彩虹表攻擊
    > Pre-Computed Hashes
    > 預先計算好的雜湊表(把可能的密碼先進行雜湊，再比對)
    :::danger
    考試重點------(12)
    :::

    - 破解方法：
        1. mkpasswd.net
        2. 直接拿雜湊去google
        3. 也可以拿去彩虹表格(預先計算好的雜湊表)找
    - 解決方法：
        1. salt
            > Linux密碼有撒鹽，windows沒有
            > 撒鹽(salt):用隨機數值讓每次雜湊結果不一樣(第二個$)
            - Salt: 層層加密
                ![](https://i.imgur.com/sw5HLCI.png =50%x)
            
            - 密碼都一樣 但雜湊不一樣
                ![](https://i.imgur.com/L8Rivy0.png)
            
            - 分析一下發現可以用 $ 分割 ($5代表sha-256)
                ![](https://i.imgur.com/vNvGFi3.png)
        2. pepper

2. Distributed Network Attack
    > 分散式網路攻擊
    > 在網路上找很多機器，做協同運算把密碼破解掉(不過現在都找GPU server)
    
    > A Distributed Network Attack (DNA) 
    > is a technique used for recovering password-protected files that utilize the unused processing power of machines spread across the network to decrypt passwords.
    :::danger
    考試重點------(13)
    :::

## Cracking Tools
### Tools to Extract the Password Hashes
1. pwdump7， 工具：[pwdump7](https://www.tarasco.org)
2. Mimikatz (https://github.com)
3. Powershell Empire (https://github.com) 
4. DSInternals PowerShell (https://github.com) 
5. Ntdsxtract (https://github.com)

### password-Cracking Tool
1. L0phtCrack(https://www.l0phtcrack.com)
2. ophcrack(http://ophcrack.sourceforge.net)
3. RainbowCrack(http://project-rainbowcrack.com)
4. John the Ripper (https://www.openwall.com) 
5. hashcat (https://hashcat.net) 
6. THC-Hydra (https://github.com) 
7. Medusa (http://foofus.net)

## Vulnerability Exploitation
### Steps on Exploiting vulnerabilities
1. Identify the Vulnerability
2. Determine the Risk Associated with the Vulnerability 
3. Determine the Capability of the Vulnerability
4. Develop the Exploit
5. Select the Method for Delivering – Local or Remote
6. Generate and Deliver the Payload
7. Gain Remote Access 

### Exploit Sites
- Exploit Database(https://www.exploit-db.com)

### Buffer Overflow
> A buffer is an area of adjacent memory locations allocated to a program or application to handle its runtime data. 
> Buffer overflow or overrun is a common vulnerability in applications or programs that accept more data than the allocated buffer. This vulnerability allows the application to exceed the buffer while writing data to the buffer and overwrite neighboring memory locations. Furthermore, this vulnerability leads to erratic system behavior, system crash, memory access errors, etc. 

> Attackers exploit a buffer overflow vulnerability to inject malicious code into the buffer to damage files, modify program data, access critical information, escalate privileges, gain shell access, and so on
- 緩衝區溢位，理論上可以透過緩衝區溢位去竄改程式碼

### Privilege Escalation
> 提權
> Privilege escalation 
> is required when you want to access the system resources that you are not authorized to access. 

#### Types of Privilege Escalation
1. 水平提權(Horizontal Privilege Escalation)
    - ex: administor -> system
2. 垂直提權(Vertical Privilege Escalation)
    - ex: user -> admin

#### Privilege Escalation Using DLL Hijacking 
> 透過DLL檔設定的問題，再DLL裡面把程式碼片段置換掉

- 動態資料抓取
    | OS      | DLL                    | Tools                                             |
    | ------- | ---------------------- | ------------------------------------------------- |
    | Windows | DLL                    | [Robber]( https://github.com)->掃描設定檔有無問題    |
    | Linux   | SO (share object)      |                                                   |
    | MacOS   | DyLib (dynmic library) | DylibHijack                                       |

  
#### 時事
- 2022 Linux 漏洞，[dirty pipe](https://www.ithome.com.tw/news/149763)
- linux pwnkit，[linux pwnkit](https://www.informationsecurity.com.tw/article/article_detail.aspx?aid=9696)

### Privilege Escalation Using Spectre and Meltdown
> 可預測執行缺陷
1. Spectre Vulnerability (幽靈漏洞)
    > The Spectre vulnerability 
    > is found in many modern processors, including Apple, AMD, ARM, Intel, Samsung, and Qualcomm processors. This vulnerability allows attackers to trick a processor into exploiting speculative execution to read restricted data. 
    - 可以看到隔壁Process的漏洞
    
2. Meltdown Vulnerability (溶斷漏洞)
    > Meltdown vulnerability 
    > is found in all Intel and ARM processors deployed by Apple. This vulnerability allows attackers to trick a process into accessing out-of-bounds memory by exploiting CPU optimization mechanisms such as speculative execution. 
    - 提權，改寫隔壁記憶體的內容

### Privilege Escalation using Named Pipe Impersonation
> Process之間的通訊，透過通訊找到更高權限的Process讓它代理執行

> In Windows OS, named pipes are used to provide legitimate communication between running processes. In this technique, the messages are exchanged between the processes using a file. 

### Privilege Escalation by Exploiting Misconfigured Services 
- Unattended Installs(無人安裝檔)
    - 需要高權限
    - 如果不小心找到就可以拿到高權向帳密

### Pivot and Relaying to Hack External Machines
> 跳板攻擊
- Pivoting(軸心)
    - 過程：利用跳板攻擊(client1)攻擊其他機器(client2)
    - 目的：攻擊client2(攻擊對象的IP就是clint2)，經過client1(跳板)去打
    - 攻擊對象：client2
    <img src="https://2761223348-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MdS6Wp-xQVaHk-LWQlD%2F-MgbmYDd7oIDpq57IGXN%2F-MgbnMrEXVJMMt25WSvG%2Fimage.png?alt=media&token=9becf9d2-9ddf-49b3-b3e6-0e6cdce98cae" height=300/>
- Relaying(轉接)
    - 過程：利用轉接(client1)，轉接到(client2)
    - 目的：攻擊client2(攻擊對象的IP是clint1)，隔山打牛?
    - 攻擊對象：client1
    <img src="https://2761223348-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MdS6Wp-xQVaHk-LWQlD%2F-MgbmYDd7oIDpq57IGXN%2F-MgbnQB3_7d-NwgzXwWB%2Fimage.png?alt=media&token=386f13d2-b461-48c9-8b2c-2fad0575e7c5" height=300 />

## Executing Application
The malicious programs attackers execute on target systems can be: 
- Backdoors:
    Program designed to deny or disrupt the operation, gather information that leads to exploitation or loss of privacy, or gain unauthorized access to system resources.
- Crackers
    Components of software or programs designed for cracking a code or passwords.
- Keyloggers
    These can be hardware or software. In either case, the objective is to record each keystroke made on the computer keyboard.
- Spyware
    Spy software may capture screenshots and send them to a specified location defined by the hacker. For this purpose, attackers have to maintain access to victims’ computers. After deriving all the requisite information from the victim’s computer, the attacker installs several backdoors to maintain easy access to it in the future.

### Remote Code Execution Techniques
- Exploitation for Client Execution
    - Web-Browser-Based Exploitation
    - Office-Applications-Based Exploitation
    - Third-Party Applications-Based Exploitation
- Scheduled Task
- Service Execution
- Windows Management Instrumntation(WMI)
    > WMI is a feature in Windows administration that manages data and operations on Windows OSs and provides a platform for accessing Windows system resources locally and remotely.
- Windows Remote Management(WinRM)
    > WinRM is a Windows-based protocol designed to allow a user to run an executable file to modify system services and the registry on a remote system.
    
    > Attackers can use the winrm command to interact with WinRM and execute a payload on the remote system as a part of lateral movement.

### Tools for Executing Applications
1. RemoteExec (https://www.isdecisions.com)
2. Pupy (https://github.com) 
3. PDQ Deploy (https://www.pdq.com) 
4. Dameware Remote Support (https://www.dameware.com) 
5. ManageEngine Desktop Central (https://www.manageengine.com) 
6. PsExec (https://docs.microsoft.com)
    ```bash=
    # windows
    use \\10.10.10.16 qwerty /u:jason
    \Pstools\PsExec.exe \\10.10.10.16 cmd.exe
    ```
    
    ```bash=
     # linux
     # 這邊的密碼用hash也可以過
    winexe -U 'administrator%Pa$$w0rd' //10.10.10.16 cmd.exe
    ```
    ![](https://i.imgur.com/r7h4UPC.png)
    
#### Keylogger   
1. Software Keystroke Loggers
2. Hardware Keyloggers 
3. 工具：[KeyGrabber]( https://www.keydemon.com)

#### Hardware keyloggers
1. KeyGrabber USB(http://www.keelog.com) 
2. KeyCarbon (http://www.keycarbon.com) 
3. Keyllama Keylogger (https://Keyllama.com) 
4. Keyboard logger (https://www.detective-store.com) 
5. KeyGhost (http://www.keyghost.com)
    
#### keyloggers  for Windows 
- [Spyrix Keylogger Free](http://www.spyrix.com)
- REFOG Personal Monitor (https://www.refog.com) 
- All In One Keylogger (http://www.relytec.com) 
- Elite Keylogger (https://www.elitekeyloggers.com) 
- StaffCop Standard (https://www.staffcop.com) 
- Spytector (https://www.spytector.com)

### Spyware 
> 鍵盤側錄器
#### Spyware Tools
1. Spytech SpyAgent，[網站](https://www.spytech-web.com)
2. Power Spy，[網站](http://ematrixsoft.com)

:::spoiler Spyware Tools
####  Desktop and Child-Monitoring Spyware
- ACTIVTrak (https://activtrak.com) 
- Veriato Cerebral (http://www.veriato.com) 
- NetVizor (https://www.netvizor.net) 
- SoftActivity Monitor (https://www.softactivity.com) 
- SoftActivity TS Monitor (https://www.softactivity.com)
#### USB Spyware
The following is a list of USB spyware: 
- USB Analyzer (https://www.eltima.com) 
- USB Monitor (https://www.hhdsoftware.com) 
- USBDeview (https://www.nirsoft.net) 
- Advanced USB Port Monitor (https://www.aggsoft.com) 
- USB Monitor Pro (http://www.usb-monitor.com)
#### Cellphone Spyware
Some of the available telephone/cellphone spyware programs are as follows: 
- Phone Spy (https://www.phonespysoftware.com)
- XNSPY (https://xnspy.com) 
- iKeyMonitor (https://ikeymonitor.com) 
- OneSpy (https://www.onespy.in) 
- TheTruthSpy (https://thetruthspy.com)
####  GPS Spyware
Some examples of GPS spyware programs are listed as follows: 
- Spyera (https://spyera.com) 
- mSpy (https://www.mspy.com) 
- MOBILE SPY (http://www.mobile-spy.com) 
- MobiStealth (https://www.mobistealth.com) 
- FlexiSPY (https://www.flexispy.com)
:::

## Hidding Files
### Rootkits
> 用來隱藏程式的程式
> Rootkits 
> are software programs designed to gain access to a computer without being detected. They are malware that help attackers gain unauthorized access to a remote system and perform malicious activities. The goal of a rootkit is to gain root privileges to a system.

#### The attacker places a rootkit by 
- Scanning for vulnerable computers and servers on the web 
- Wrapping the rootkit in a special package like a game 
- Installing it on public or corporate computers through social engineering 
- Launching a zero-day attack (privilege escalation, Windows kernel exploitation, etc.)
#### Objectives of a rootkit: 
- To root the host system and gain remote backdoor access
- To mask attacker tracks and presence of malicious applications or processes
#### Types of Rootkits
1. Hypervisor Level Rootkit
    > Hardware Level
    > Attackers create hypervisor-level rootkits by exploiting hardware features such as Intel VT and AMD-V.

    - 偵測Rootkits，好用工具: GMER
        - detect and removes rootkits
        - 功能太強，效果像化療
2. Kernel-Level Rootkit
3. Boot-Loader-Level Rootkit
4. Application-Level/User-Mode Rootkit
5. Library-Level Rootkits

#### Rootkits Tools
1. Lojax，[網址](https://www.welivesecurity.com)
2. Scranos，[網址](https://www.bitdefender.com)
3. Horse Pill，[網址](http://www.pill.horse)
4. Necurs，[網址](https://www.f-secure.com) 
#### 時事
- UEFI 漏洞事件，[網址](https://technews.tw/2018/10/01/eset-uefi-rootkit-lojax/)

### NTFS data stream
- 更改前
    ![](https://i.imgur.com/tumh52V.png =300x)

- 更改後
    ![](https://i.imgur.com/YPD8Ylx.png =300x)
    > size太小 系統算0 byte
- 改副檔名
    ```bash===
    #windows 建立附檔名
    notepad hello.txt:yy.txt
    ``` 
- 資料放在硬碟上，但看不到
    ![](https://i.imgur.com/hpLS4c1.png)

- 使用指令
    ```bash===
    # windows 就看的到了
    dir /r
    ``` 
    ![](https://i.imgur.com/Dend9m7.png)

- 背後偷偷執行
    ```bash=
    # 可以偷偷執行
    type \Windows\System32\cmd.exe > hello.txt:yy.txt
    ```
    ```text=
    wmic process call create c:/test/hello.txt:yy.exe
    ```
## Steganography
> 把資料隱藏在資料
> Steganography 
> refers to the art of hiding data “behind” other data without the knowledge of the victim.

### Image Steganograpghy
- 常用工具：s-tools
- 執行步驟：
    1. 執行exe後把圖片放進去，右下會顯示可以偷存的資料大小
    2. 在把檔案丟進去，可以設密碼，再左建存檔
    3. 檔案大小會一樣
    4. 因為檔案存在每個位元的最小bit裡，導致每個像速差一個色階(看不出來)

### Whitespace Steganograpghy
- 常用工具：snow，[網址](http://www.darkside.com.au)
- 指令
    ```bash=
    snow -C -m "test" -p "magic" readme.txt readme2.txt
    ```
- 隱藏手法:變成空白或隱藏字元:txt不顯示但資料在

### video steganography
- OmniHide Pro，[網址](http://omnihide.com)

### Steganography Detection Tools
1. zsteg (https://github.com)
2. StegoVeritas (https://github.com) 
3. Stegextract (https://github.com) 
4. StegoHuntTM (https://www.wetstonetech.com) 
5. Steganography Studio (http://stegstudio.sourceforge.net) 
6. Virtual Steganographic Laboratory (VSL)(http://vsl.sourceforge.net)


## Clearing Logs 
> 隱藏蹤跡的方式：關log紀錄、清log
### Clearing Logs Tools
> Clear_Event_Viewer_Logs.bat is a utility that can be used to wipe out the logs of the target system. This utility can be run through command prompt, PowerShell, and using a BAT file to delete security, system, and application logs. 

> Attackers might use this utility to wipe out the logs as one method of covering their tracks on the target system. 
- Steps to clear logs using Clear_Event_Viewer_Logs.bat utility are as follows. 
    1. Download the Clear_Event_Viewer_Logs.bat utility from https://www.tenforums.com.
    2. Unblock the .bat file. 
    3. Right-click or press and hold on the .bat file and click/tap on Run as administrator. 
    4. If prompted by UAC, click/tap on Yes.
    5. A command prompt will now open to clear the event logs. The command prompt will automatically close when finished.
### windows 
- 缺點：會把清log的人記錄下來
- 解決辦法:提權後用system role 清除
- 如果能把MRU(most recently used)全部清掉，看起來就會像沒用過
### Linux 清指令
- 一開始就不要存
    - export HITSIZE=0
- 把歷史清除
    - history -c(Clears the stored history)

## CH06 Practice
1. [Lab 1.1] Perform Active Online Attack to Crack the System’s Password using Responder
2. [Lab 1.2] Audit System Passwords using L0phtCrack