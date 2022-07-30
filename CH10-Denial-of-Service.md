{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH10-Denial-of-Service
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/22(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 目標:癱瘓目標伺服器的服務
---

## DOS / DDOS Concepts
### DOS 
> Denial-of-Service(DoS) attack 
> is an attack on a computer or network that reduces, restricts, or prevents access to system resources for legitimate users. In a DoS attack, attackers flood a victim’s system with nonlegitimate service requests or traffic to overload its resources and bring down the system, leading to the unavailability of the victim’s website or at least significantly reducing the victim’s system or network performance.

- cause
    - **Service / System destruction**
    - Consumption of resources 
    - Consumption of bandwidth, disk space, CPU time, or data structures 
    - Actual physical destruction or alteration of network components 
    - Destruction of programming and files in a computer syste

### DDoS
> Distributed Denial-of-Service(DDoS)
> A DDoS attack 
> is a large-scale, coordinated attack on the availability of services on a victim’s system or network resources, and it is launched indirectly through many compromised computers (botnets) on the Internet.

- cause
    -  Resource consumption (Bandwidth, Connection, CPU, Memory)

## DoS/DDoS Attack Techniques

### Basic Categories of DoS/DDoS Attack Vector
1. Volumetric Attacks
2. Protocol Attacks
3. Apllication Layer Attacks

### 1. Volumetric Attacks
> These attacks exhaust the bandwidth either within the target network/service or between the target network/service and the rest of the Internet to cause traffic blockage, preventing access to legitimate users.
- 打量(頻寬)
- The magnitude of attack is measured in <font color="red">bits-per-second(bps)</font>
- two types of bandwidth depletion attacks
    - flood attack
        - ex: SYN flood Attack (多個機器在三項交握第三步時遲遲不回應伺服器 占用助服務)
    - amplification attack
        - EX:由很多的 Zombie 同時發送 request 到 target 

:::warning
 ### attacks generally target protocols such as 
 (stateless and do not have built-in congestion avoidance features)
 1. the Network Time Protocol (NTP)
 2. Domain Name System (DNS)
 3. Simple Service Discovery Protocol (SSDP) 
:::

:::info 
### volumetric attack techniques
- UDP flood attack 
- ICMP flood attack
- Ping of Death(PoD) Attack 
    > 藉由畸形封包攻擊系統
- Smurf Attack (Smurf 藍色小精靈) (考)
    > 目的：攻擊者假冒別人的IP
    > 說明：Smurf攻擊通過使用將回復地址設定成受害網路的廣播地址的ICMP應答請求(ping)數據包，來淹沒受害主機，最終導致該網路的所有主機都對此ICMP應答請求做出答覆，導致網路阻塞。
    - DRDoS分散反射(放大)阻斷服務攻擊
        > distributed reflection denial of service(DRDoS)
        - ex. 用別人foodpanda帳號訂購全台北麥當勞套餐
- Pulse wave attack
    > 類似一波一波海浪襲來
- zero-day attack
    - 漏洞爆出來後還沒修就被攻擊
    > 零日漏洞或零時差漏洞
    > 通常是指還沒有修補程式修補程式的安全漏洞
    > 零日攻擊或零時差攻擊則是指利用這種漏洞進行的攻擊
:::



### 2. Protocol Attacks
> Protocol DDoS attacks 
> exhaust resources available on the target or on a specific device between the target and the Internet. These attacks consume the connection state tables present in network infrastructure devices such as load balancers, firewalls, and application servers. 
- 打設備
- The magnitude of attack is measured in <font color="red">packets-per-second(pps)</font>
- ex. 3000塊分為3000個一塊，消耗資源

:::info
### protocol attack techniques

- SYN flood attack
    > 目的:消耗目標連線數量
- Fragmentation attack
    - 打設備
    - 細碎封包，讓目標系統重組，拖慢目標CPU速度
- spoofed session flood attack
    - [mirai ovh](https://zh.wikipedia.org/zh-tw/Mirai_%E6%81%B6%E6%84%8F%E8%BD%AF%E4%BB%B6)
- ACK flood attack
:::
    

### 3. Apllication Layer Attacks
> Attacks on unpatched, vulnerable systems do not require as much bandwidth as protocol or volumetric DDoS attacks for succeeding. In application DDoS attacks, the application layer or application resources are consumed by opening connections and leaving them open until no new connections can be made. 
- 打服務
- The magnitude of attack is measured in <font color="red">requests-per-second(rps) (每秒所發動的請求數)</font>
- 低頻寬式攻擊
    - ex: 7-11結帳 前面的人拿一堆一塊付

:::info
### Apllication Layer Attack Techniques
- HTTP GET/POST attack
- Slowloris attack (常考)
- UDP application layer flood attack
    - 打量
- Multi-Vector Attack
    - 多維攻擊
    - mirai botent
        - 主要影響比較低階的電子設備(ex: 網路攝像監視器 家庭路由器等)讓他們當Zombie攻擊
- permanent DoS(PDoS) attack 
    - 又稱phlashing(網路刷機) 
    - https://blog.trendmicro.com.tw/?tag=phlashing
    - 這是一種永久阻斷服務攻擊 (簡稱 PDoS)，利用硬體裝置的安全漏洞，直接破壞裝置的韌體。
    - ex: 利用裝置的預設密碼進入後把重要的系統參數改掉(linux指令等等)使裝置永久損壞
- Distributed reflection DoS (DRDoS) attack
    - 又稱為"spoofed" attack
    - 濫用公開網絡服務進行分散式反射阻斷服務（DRDoS）攻擊
    - 放大流量 
    - 常用攻擊：DNS、NTP、SNMP
:::
    

## DoS/DDoS Attack Tools
> This section deals with various DoS/DDoS attack tools used to take over a single or multiple network system to exhaust their computing resources or render them unavailable to their intended users.
DoS/DDoS Attack Tools 
- High Orbit Ion Cannon (**HOIC**)
    - Source: https://sourceforge.net
    - High-speed multi-threaded HTTP flooding 
    - Simultaneous flooding of up to 256 websites 
    - Built-in scripting system to allow the deployment of “boosters,” which are scripts designed to thwart DDoS countermeasures and increase DoS output
    - Portability to Linux/Mac with a few bug fixes 
    - Ability to select the number of threads in an ongoing attack 
    - Ability to throttle attacks individually with three settings: LOW, MEDIUM, and HIGH
- Low Orbit Ion Cannon (**LOIC**) 
    - Source: https://sourceforge.net 
    > LOIC is a network stress testing and DoS attack application.
    > LOIC attacks can be called application-based DOS attacks because they primarily target web applications. 
    > LOIC can be used on a target site to flood the server with TCP packets, UDP packets, or HTTP requests with the intention of disrupting the service.

:::spoiler other DoS/DDoS attack tools
- **XOIC** (http://anonhacktivism.blogspot.com) 
- HULK (https://siberianlaika.ru) 
- Tor’s Hammer (https://sourceforge.net) 
- **Slowloris** (https://github.com) 
- PyLoris (https://sourceforge.net) 
- R-U-Dead-Yet (https://sourceforge.net)
:::


### DoS/DDoS Attack Tools for Mobiles
- LOIC，[LOIC](https://play.google.com)
- AnDOSid，[AnDOSid](https://andosid.droidinformer.org) 
- Packets Generator，[Packets Generator](https://play.google.com) 

## Scanning Methods for Finding Vulnerable Machines
:::danger
考試重點，考種類
:::
1. Random Scanning
    - 隨機打
2. Hit-list Scanning
3. Topological Scanning
    - 用目標機器，成功後，接著往下攻擊
4. Local Subnet Scanning
    - 在區網裡找
6. Permutation Scanning
    - 隨機一個清單，看誰打誰

## Security Events
- [DDoS 事件-Great cannon](https://zh.wikipedia.org/zh-tw/%E5%A4%A7%E7%82%AE_(%E7%BD%91%E7%BB%9C%E6%94%BB%E5%87%BB%E5%B7%A5%E5%85%B7))


## CH10 Practice
1. [lab 1-2] hping 3


