{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH08-Sniffing
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/22(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 透過**封包側錄**獲取資料
---

:::warning
### 必考重點
- promiscuous mode(雜亂模式)
:::

## Sniffing Concepts
### Network Sniffing 
> Packet sniffing is the process of monitoring and capturing all data packets passing through a given network using a software application or hardware device.


## Types of Sniffing
1. passing sniffing
2. active sniffing

### 1. passing sniffing
> Passive sniffing involves sending no packets. It simply captures and monitors the packets flowing in the network.

> 如果：是透過hub 可以看到封包
> 所以：現在都是用switch，區隔不必要的封包
> 因此：攻擊SWITCH就有機會看到自己要的封包

### 2. active sniffing
> Active sniffing 
> searches for traffic on a switched LAN by actively injecting traffic into it

1. mac flooding
2. DNS poisoning
3. ARP posisoning DHCP attack
4. Switch port stealing
5. spoofing attack

## Protocols Vulnerable to Sniffing
1. Telnet
    - port:23
    > Telnet
    > is a protocol used for communicating with a remote host (via port 23) on a network using a command-line terminal.
2. HTTP
    > HTTP transfer user data across the network in plaintext, which attackers can read to steal user credentials.

3. POP
    > Post Office Protocol (POP) 
    > allows a user’s workstation to access mail from a mailbox server. 
4. IMAP
    > Internet Message Access Protocol (IMAP)
    > allows a client to access and manipulate electronic mail messages on a server. 
5. SMTP
    > Simple Mail Transfer Protocol (SMTP)
    > is used for transmitting email messages over the Internet. 
6. FTP
    > File Transfer Protocol (FTP) 
    > enables clients to share files between computers in a network. 
7. NNTP
    > Network News Transfer Protocol (NNTP) 
    > distributes, inquires into, retrieves, and posts news articles using a reliable stream-based transmission of news among the ARPA-Internet community. 

## Sniffing in the Data Link Layer of the OSI Model
### SPAN port
> Switched Port Analyzer (SPAN)
> is a Cisco switch feature, also known as “port mirroring,” that monitors network traffic on one or more ports on the switch. A SPAN port is a port that is configured to receive a copy of every packet that passes through a switch.
- port mirror

### WireTapping
> Wiretapping, or telephone tapping, refers to the monitoring of telephone or Internet conversations by a third party with covert intentions. To perform wiretapping, the attacker first selects a target person or host on the network to wiretap and then connects a listening device (hardware, software, or a combination of both) to the circuit carrying information between the two target phones or hosts. 
- 實體封包側錄工具：network tap(網路流量分量器)

## Sniffing Technique: MAC Attacks 


### mac flooding
> mac flooding 讓 CAM table is full 達成攻擊

#### CAM table 
> CAM table
> is a dynamic table of fixed-size. It stores information such as MAC addresses available on physical ports along with VLAN parameters associated with them. 

> - store information
> - content addressable memory

<!-- ### 假照卡號攻擊 -->


#### 攻擊流程
1. 發送大量封包
2. switch不知道目標在哪(CAM table滿了)
3. 破壞switch隔絕網路封包的機制

-  This tool floods the switch’s CAM tables (131,000 per min) by sending forged MAC entries.
    ```shell=
    # Unix
    macof -i eth0 -n 10
    ```

### switch port stealing
> The switch port stealing 
> sniffing technique uses MAC flooding to sniff the packets. The attacker floods the switch with forged gratuitous ARP packets with the target MAC address as the source and his/her own MAC address as the destination.
- 假造port去騙switch，誘導switch將封包發送到錯誤位置

## Sniffing Technique: DHCP Attacks

### How DHCP Works
> DHCP is a client–server protocol that provides an IP address to an IP host. 

### DHCP starvation attack
> In a DHCP starvation attack, 
> an attacker floods the DHCP server by sending numerous DHCP requests and uses all of the available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to a DoS attack. 
> Because of this issue, valid users cannot obtain or renew their IP addresses; thus, they fail to access their network.

- Attacker：假造DHCP請求訊息->拿到DHCP所有的IP
- 結果: DHCP沒有IP可以發送-> User要不到IP

:::spoiler DHCP Starvation Attack Tools
- Yersinia，[Yersinia](https://sourceforge.net) 
- Hyenae (https://sourceforge.net)
- dhcpstarv (https://github.com) 
- Gobbler (https://sourceforge.net) 
- DHCPig (https://github.com) 
:::
    
### rogue DHCP Starvation attack
> In addition to DHCP starvation attacks, an attacker can perform MITM attacks such as sniffing. An attacker who succeeds in exhausting the DHCP server’s IP address space can set up a rogue DHCP server on the network, which is not under the control of the network administrator.

> 當DHCP starvation attack成功，就可以藉由MITM attacks 達到架設rogue DHCP server並且監察

- 亂入: 亂發IP

### Defend Against DHCP Starvation and Rogue Server Attacks
#### Defend Against DHCP Starvation
- Enable port security
    - Port security limits the maximum number of MAC addresses on the switch port. When the limit is exceeded, the switch drops subsequent MAC address requests (packets) from external sources, which safeguards the server against a DHCP starvation attack.

#### Dfend Against Rogue Server Attack
- DHCP snooping
    - It is configured on the port on which the valid DHCP server is connected. Once configured, DHCP snooping does not allow other ports on the switch to respond to DHCP Discover packets sent by clients. 
    - 監控DHCP

## Sniffing Technique: ARP Poisoning 
###  What is ARP
> resolving IP addresses to machine(MAC) addresses

> ARP 位置解析通訊協定
> 以IP為基準，查詢MAC address

- 查詢ARP
    ```shell=
    arp -a
    ```

### ARP Spoofing Attack
- 對的IP對應到錯的卡號，中間人攻擊
- 工具：cain & abel
    - [Cain & abel ARP汙染攻擊](https://mmdays.com/2008/11/10/mitm/) 

### Threats of ARP Poisoning
- Packet Sniffing
- VoIP Call Trapping
- Manipulating Data
- Man-in-the-Middle Attack
- Data Interception
- Connection Hijacking
- Connection Resetting
- Stealing Passwords
- DoS Attack

#### ARP Poisoning Tools
- arpspoof，[arpspoof](https://linux.die.net)
    ```shell=
    arpspoof –i [Interface] –t [Target Host]
   ```
- BetterCAP (https://www.bettercap.org) 
- Ettercap (http://www.ettercap-project.org) 
- dsniff (https://www.monkey.org) 
- MITMf (https://github.com) 
- Arpoison (https://sourceforg)

#### ARP Spoofing Detection Tools
- XArp，[XArp](http://www.xarp.net)
- Capsa Network Analyzer (https://www.colasoft.com) 
- ArpON (https://sourceforge.net) 
- ARP AntiSpoofer (https://sourceforge.net) 
- ARPStraw (https://github.com) 
- shARP (https://github.com)

## Sniffing Technique: Spoofing Attacks
### MAC Spoofing/Duplicating MAC duplicating
> refers to spoofing a MAC address with the MAC address of a legitimate user on the network. 
> A MAC duplicating attack involves sniffing a network for MAC addresses of legitimate clients connected to the network. 
> In this attack, the attacker first retrieves the MAC addresses of clients who are actively associated with the switch port.
> 
### IRDP Spoofing
> ICMP Router Discovery Protocol (IRDP)
> is a routing protocol that allows a host to discover the IP addresses of active routers on its subnet by listening to router advertisement and solicitation messages on its network. 
> The attacker can add default route entries on a system remotely by spoofing router advertisement messages.
- 利用廣播的方式探索網路上的router


### VLAN Hopping
:::danger
考試會考
:::
> VLAN hopping
> is a technique used to target network resources present on a virtual LAN
> Attackers perform VLAN hopping attacks to steal sensitive information such as passwords; modify, corrupt, or delete data; install malicious codes or programs; or spread viruses, Trojans, and worms throughout the network.

#### 兩種VLAN hopping
1. switch spoofing(交換欺騙)
   - 攻擊者偽裝成交換機，從而欺騙合法交換機在二者之間建立中繼鏈路
2. double Tagging(雙重標記)
    - 攻擊者在乙太網幀上新增或修改標記，從而允許通過任何VLAN傳送資料包，這種方法就叫做雙重標記。
    - 利用假造封包，以為視同個VLAN


### STP Attack
:::danger
考試會考
:::
#### spanning tree alogrithm
> STP is used in LAN-switched networks with the primary function of removing potential loops within the network. STP ensures that the traffic inside the network follows an optimized path to enhance network performance. 

#### STP attack
> In a Spanning Tree Protocol (STP) attack, 
> attackers connect a rogue switch into the network to change the operation of the STP protocol and sniff all the network traffic. 

> If an attacker has access to two switches, he/she introduces a rogue switch in the network with a priority lower than any other switch in the network. This makes the rogue switch the root bridge, thus allowing the attacker to sniff all the traffic flowing in the network.
- 連接層攻擊
- rouge會把自己的權重拉高變成tree root
- STP Hijack
    - 因為是root 所以在行程VLAN中的生成樹網路時一定會經過attacker，進而去竊聽資料


## Sniffing Technique: DNS Poisoning
### Intranet DNS Spoofing
> An attacker can perform an intranet DNS spoofing attack on a switched LAN with the help of the ARP poisoning technique.

### Internet DNS Spoofing
> Internet DNS poisoning is also known as remote DNS poisoning. 
> Attackers can perform DNS spoofing attacks on a single victim or on multiple victims anywhere in the world. 
> To perform this attack, the attacker sets up a rogue DNS server with a static IP address. 

- tricks a DNS server
- www.google.com->IPv4 原本是172.217.163.36
- 透過Cain & abel可以更改IP解析IP

### Proxy Server DNS Poisoning
> In the proxy server DNS poisoning technique, the attacker sets up a proxy server on the attacker’s system. 
> The attacker also configures a fraudulent DNS and makes its IP address a primary DNS entry in the proxy server. 

### DNS Cache Poisoning
> DNS cache poisoning 
> refers to altering or adding forged DNS records in the DNS resolver cache so that a DNS query is redirected to a malicious site. The DNS system uses cache memory to hold the recently resolved domain names. The attacker populates it with recently used domain names and their respective IP address entries. 

- 對cache下手，可利用性低

:::spoiler DNS Poisoning Tools
- DerpNSpoof (https://github.com)
- DNS Spoof (https://github.com) 
- DNS-poison (https://github.com) 
- Ettercap (http://www.ettercap-project.org) 
- Evilgrade (https://github.com)
- TORNADO (https://github.com)
:::
#### How to defend DNS Spoofing
:::spoiler Countermeasures that help prevent DNS spoofing attacks
- Implement Domain Name System Security Extension (DNSSEC) 
- Use Secure Socket Layer (SSL) for securing the traffic 
- Resolve all DNS queries to a local DNS server 
- Block DNS requests being sent to external servers 
- Configure a firewall to restrict external DNS lookup 
- Implement an intrusion detection system (IDS) and deploy it correctly 
- Configure the DNS resolver to use a new random source port for each outgoing query 
- Restrict the DNS recusing service, either full or partial, to authorized users 
- Use DNS non-existent domain (NXDOMAIN) rate limiting 
- Secure your internal machines 
- Use static ARP and IP tables 
- Use SSH encryption 
- Do not allow outgoing traffic to use UDP port 53 as a default source port 
- Audit the DNS server regularly to remove vulnerabilities 
- Use sniffing detection tools 
- Do not open suspicious files 
- Always use trusted proxy sites 
- If a company handles its own resolver, it should be kept private and well protected
- Randomize source and destination IP addresses 
- Randomize Query ID 
- Randomize case in the name requests 
- Use Public Key Infrastructure (PKI) to protect the server 
- Maintain a single or specific range of IP addresses to log in to the systems 
- Implement packet filtering for both inbound and outbound traffic 
- Restrict DNS zone transfers to a limited set of IP addresses
:::

### sniffing tools
- wireshark
    - display filter
### sniffer detect technique
- ping method
- DNS Method

#### Packet Sniffing Tools for Mobile Phones 
- Sniffer Wicap，(https://play.google.com) 
> This tool is a mobile network packet sniffer for ROOT ARM droids. It works on rooted Android mobile devices.

## CH08 Practice
1. [2.1] Perform Password Sniffing using Wireshark
2. [3.1] Detect ARP Poisoning in a Switch-Based Network


