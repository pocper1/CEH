{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH03-Scanning Networks
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/01(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]
### 概要
> 這章跟指令語法比較有關
> 本章目標: to discover ip, ports, services, operating systems

---

## Types of Scanning
- Port Scanning
- Network Scanning
- Vulnerability Scanning

## TCP Header
![](https://i.imgur.com/9hzmADp.png =60%x)
三項交握
Sender        Reciver
-> syn
<- syn+ack
-> ack
三項交握(中斷連線)
-> fin
<- ack
<- fin
-> ack
- tcp flag
    - URG
    - ACK 
    - PSH
    - RST (reset flag)
    - SYN (同步)
        - 三橡膠握第二步
    - FIN (結束)

## Scanning Tools 
### hping 
- http://www.hping.org
> 目的：封包產生工具 (產出任何想產出的封包)
```shell=
sudo hping3 10.10.10.16 -p 80 -S -c 3 -n
```
> 對10.10.10.16的port 80，-A ACK flag, -p port, -c packet count
- example:
![](https://i.imgur.com/UOyUaWi.png)

### Metasploit
### NetScanTools Pro

### wireshark test
- icmp
```shell=
sudo hping3 8.8.8.8 -a 1.3.3.7
```

- 用wireshark看就會發現IP假冒成1.3.3.7了
- 提問: 如何判斷真假IP?




## Nmap 
- https://nmap.org
- $ nmap <options> <Target IP Address>
> Nmap 最強大的網路掃描工具
:::danger
本章重點，參數會考
- [網友整理的指令，考前可以看這篇](https://ithelp.ithome.com.tw/articles/10270754)
:::


### ping scan
:::danger
必考
:::
```shell=
nmap -sn -PR 10.10.10.* --packet-trace
```

![](https://i.imgur.com/XVAAtBh.png)

- 由443 port知道這個IP是活的
    - icmp type:8 (ping)

### TCP SYN Ping Scan
```shell=
nmap -sn -PS 10.10.10.10
```
### TCP ACK Ping Scan
```shell=
nmap -sn -PA 10.10.10.10
```
### IP portocol ping scan
```shell=
nmap -sm -PO 10.10.10.10
```
## Port Scanning Techniques
### TCP Scanning:
#### Open TCP Scanning Methods
- TCP Connect/Full Open Scan
    - 三項交握Scan
        - 參數: -sT
1. Scan result when port is open
> Attacker Target
> SYN ->
> SYN+ACK <-
> ACK ->
> RST ->
2. Scan result when a port is closed
> Attacker Target
> SYN ->
> RST <- 
3. `nmap -sT -v 10.10.10.10`
#### Stealth TCP Scanning Methods
- Half-open Scan半掃描 (三項交握做一半)
> 目的：因為未建立連線所以不會被防火牆紀錄
> 在attacker端收到target的SYN+ACK的時候直接回傳RST中斷連線
1. 參數: -sS
        ```shell=
        sudo nmap 10.10.10.10 -sS -p80, 81
        ```
        ![](https://i.imgur.com/dgTOQPi.png)
        ![](https://i.imgur.com/Zk6rGo7.png)
2. RST有沒有ACT代表是不是有理由的拒絕
- Inverse TCP Flag Scan
> Inverse TCP Flag Scan 逆向旗標掃描
> 情境: 伺服器會把SYN都擋掉

1. 把TCP SYN Inverse掉
    - 也就是用SYN以外的六大旗標去掃描
2. 丟奇怪封包(六大旗標除了SYN)過去:
    - 有開PORT: RST
    - 沒開PORT: 沒回應
3. 種類
    - Xmas Scan
        - 參數: -sX
        - 用 FIN URG PUSH 其中之一旗標去丟
        - 有開port: 被回RST
        - 沒開port: no response
    - FIN Scan
        - 參數: -sF
    - NULL Scan
        - 參數: -sN
        - 有開: no response
    - Maimon Scan (考)
        - 和上面的很像，不過送的封包是FIN/ACK
        - 參數: -sM
        - 有開port: no response
        - 沒開port: RST
- ACK Flag Probe 
    - ACK Flag Probe Scan 
        - 送出的是 Probe(ACK) 封包
        - 參數: -sA
        - 有防火牆: no response
        - 沒防火牆: RST
    - TTL-Based Scan
        - 參數: -ttl
        - 回傳的 ttl<64 的話就是有開port
    - Window Scan
        - 參數: -sW
        - 有開的話 回傳的win值非0
#### Third Party and Spoofed TCP Scanning Methods
### UDP Scanning
#### UDP Scan
- 參數：-sU -v
```shell=
sudo nmap  -sU -v 10.10.10.10 -p137,139
```
- 有開:沒反應
- 沒開:回一個ICMP
### SCTP Scanning
#### SCTP INIT Scan
:::danger
會考
:::
- 參數：-sY -v
    ```shell=
    sudo nmap -sY -v 10.10.10.10
    ```
- 發送: INIT Chunk
    - 有開: INIt + ACK Chunk
    - 沒開: ABORT Chunk
#### SCTP COOKIE/ECHO Scanning
- 參數：-sZ
    ```shell=
    sudo nmap -sZ -v 10.10.10.10
    ```
- 發送: COOKIE ECHO Chunk
    - 有開: no response
    - 沒開: abort Chunk
### SSDP Scanning
#### SSDP and List Scanning
- List Scanning
    - 參數: -sL
### IPv6 Scanning
#### IPv6 Scanning
- 參數:-6
```shell=
sudo nmap -6
```

### Others
- 參數 -PU 
    > UDP discovery on port x Port 40125 by default
    
    ```shell
    nmap -PU
    ```
- 參數 -PE
    > echo ping scan
    
    ```shell
    nmap -PE 
    ```

### connect scan
- 參數： -sT -v
    ```shell=
    nmap -sT -v 10.10.10.10
    ```
    ![](https://i.imgur.com/ruotMNI.jpg)

- 參數： -sT
    ```shell=
    sudo nmap 10.10.10.10 -sT
    ```

    - 確認三項交握(tcp)完成度
    - 可以看哪個port有開
    ![](https://i.imgur.com/aarHBJm.png)

- 參數： -sT -p
    ```shell=
    sudo nmap 10.10.10.10 -sT -p80, 81
    ```
    ![](https://i.imgur.com/PMuo2C6.png)

    - 有開port 
        ![](https://i.imgur.com/BhluJuR.png)
    - 沒開port
        ![](https://i.imgur.com/xXiBBM8.png)
        > 看第二顆封包就好 SYN有 RST沒有

### Inverse TCP Flag Scan
> Inverse TCP Flag Scan 逆向旗標掃描
> 情境: 伺服器會把SYN都擋掉

- 把TCP SYN Inverse掉
    - 也就是用SYN以外的六大旗標去掃描
- 丟奇怪封包(六大旗標除了SYN)過去:
    - 有開PORT: RST
    - 沒開PORT: 沒回應

### Xmas Scan
- 參數： -sX
    ```shell=
    sudo nmap 10.10.10.10 -p80, 81 -sX
    ```
    ![](https://i.imgur.com/c6sobA8.png)

    ![](https://i.imgur.com/K58PQAp.png)
    - 這邊都被RST所以都沒開

:::info
Xmas Scan不適用任何Windows系統
    - 因為Windwos TCP不標準，所以不適用
    - 可以看到一般掃描port80有開，但用Xmas Scan就不行
    ![](https://i.imgur.com/01Fs8nj.png)
:::
 
### ACK Flag Probe Scan
- 參數：-sA
    ```shell=
    sudo nmap -sA 10.10.10.9 www.google.com
    ```
    ![](https://i.imgur.com/QNlbOvg.png)

- 合google.com之間有防火牆，10.10.10.9沒有(filltered,unfilltered)
- 看ttl(在IP標頭)，有不一樣的就是有開
- 看win(在TCP標頭)，有值的就是有開
    
### IDLE/IPID Header Scan
> 目的：攻擊者假造Zombie送封包
> 過程：第一次RST 31337，第二次RST 31339代表其中有31338所以Target回送Zombie一個RST，代表Target沒開Port，如果還傳SYN+ACK就是有開
> 簡單來說就是用Target做跳板傳封包給Zombie有傳到表示target port有開
- 參數：-sI
    ```shell=
    sudo nmap 10.10.10.2 -p 80 -sI 10.10.10.10
    ```
    ![](https://i.imgur.com/MonTwms.png)

:::info
閒著沒事的掃描
- Zombie要閒著沒事，因為要看Zombie的封包編號
- 封包編號要是連續號才有用
    - Linux 在kernel2後採加密封包序號，所以不能用
:::


### Attempts to determine the version of the service running on port
- 參數：-sV
    ```shell=
    sudo nmap 10.10.10.10 -sV
    ```

    ![](https://i.imgur.com/iBfK2yT.png)

### Nmap Scan Time Reduction Techniques
> 如何加快掃描時間: 少掃一點
> 為了socket programming(動態分配IP)，port 0 不能用
- 參數：-sT -p- (-p- => 1~65535)
    ```shell=
        sudo nmap 10.10.10.9 -sT -p- (-p- => 1~65535)
    ```


### How to Identify Target System OS
> 辨別OS(Wireshark) 
:::danger
會考
:::
![](https://i.imgur.com/7JrYaIj.png =60%x)
![](https://i.imgur.com/V03DS6G.png =60%x)
- 參數: -O
- TTL識別作業系統 TTL time to live
    - Linux TTL->64
    - Windows TTL->128


### OS Discovery using Nmap Script Engine
> 腳本掃描
- 參數：--script
    ```shell=
    nmap --script smb-os-discovery.nse 10.10.10.16 
    ```

#### URL rewirte
> 不顯示副檔名
- [URL rewrite](https://ithelp.ithome.com.tw/articles/10204146)

## Scanning Beyond IDS and Firewall
- IDS/Firewall Evasion Techniques
    - Packet Fragmentation
    - Source Routing
    - Source Port Manipulation
    - IP Address Decoy
    - IP Address Spoofing
    - Creating Custom Packets
    - Randomizing Host Order
    - Sending Bad Checksums
    - Proxy Servers
    - Anonymizers

### packet fragmentation
> 封包分片法
- 參數： -f
- 被切割過的IP封包，為了繞過防火牆，掃描被擋掉時可以試試看
### Source Routing
- 封包自己決定路徑，現在不能用了，內網有可能還有用
### IP Spoofing
- 參數: -a
- 假造IP封包: 假造封包裡的Source Address部分
- ![](https://i.imgur.com/7M7uE6h.png =70%x)
- 如果欄位之間兜不起來就是假的
- TTL 量測法
    - 利用TTL的標頭來判斷
    - ![](https://i.imgur.com/uvmZ0PP.png)
    - 罩門:要假造IP和被假造IP的人在同網段
        - 若在同網段，看IPID
### Proxy Chain
- 一次使用多個跳板隱藏自己
- 測試瀏覽器是否可被追蹤
    - [測試瀏覽器是否可被追蹤-coveryourtracks.eff.org](https://coveryourtracks.eff.org/kcarter?aat=1)

## CH03 Practice
1. [1-1] Perform Host Discovery using Nmap
2. [2-3] Explore Various Network Scanning Techniques using Nmap
3. [3-2] Perform OS Discovery using Nmap Script Engine(NSE)