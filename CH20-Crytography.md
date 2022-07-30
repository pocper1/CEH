{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH20-Crytography
| 事項         | 時間                              |
| ------------ | --------------------------------- |
| 上課日期     | 2022/06/25(六) 09:00 ~ 18:00      |
| 最後更新日期 | 2022/07/31(日) 01:35              |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 依數學公式或演算法將明文改為密文，目的是為了防止輕易的被猜測或取得

---

## Cryptography Concepts
### Objective of Cryptography
1. Confidentiality 可信度
2. Integrity       誠信
3. Authentication  驗證
4. Non-repudiation 不可否認性

### Types of Cryptograpghy 
:::danger
考試會考
:::
1. Symmetric Encryption
    - 對稱式加密
    - 速度快 相對安全
    <img src="https://know.zombit.info/wp-content/uploads/2019/11/%E5%B0%8D%E7%A8%B1%E5%8A%A0%E5%AF%86%E3%80%81%E9%9D%9E%E5%B0%8D%E7%A8%B1%E5%8A%A0%E5%AF%86%E8%88%87%E6%95%B8%E4%BD%8D%E7%B0%BD%E7%AB%A0-%E5%B0%8D%E7%A8%B1%E5%8A%A0%E5%AF%86.jpg" />

2. Asymmetric Encryption 
    :::info
    - 用對方的公鑰 用自己的私鑰
    - 這邊會考甚麼時候用公鑰還是私鑰
    :::
    - 非對稱式加密(RSA)

    <img src="https://know.zombit.info/wp-content/uploads/2019/11/%E5%B0%8D%E7%A8%B1%E5%8A%A0%E5%AF%86%E3%80%81%E9%9D%9E%E5%B0%8D%E7%A8%B1%E5%8A%A0%E5%AF%86%E8%88%87%E6%95%B8%E4%BD%8D%E7%B0%BD%E7%AB%A0-%E9%9D%9E%E5%B0%8D%E7%A8%B1%E5%8A%A0%E5%AF%86.jpg" />

3. Government Access to Keys(GAK)
> 政府要求廠商提供的萬能鑰匙

## Encrpytion Algorithms
> 加密演算法

### Symmetric-key algorithms (Private-key cryptography)
- 對稱式加密(私鑰)
- 技術: DES、AES、3DES、DESX、Blowfish、IDEA、RC4、RC5、RC6

1. DES
    > DES(Data Encryption Standard)
    > 封包分段加密，速度快，適用於大量資料加密，分段使用 56 bit，由於金鑰過短，故易於破解，故後續進階為AES

2. AES
    > AES(Advanced Encryption Standard)
    > 高階分段加密，以128 bit、192或256位的金鑰做加密，較為安全

3. 3DES
    > 使用3種不同密鑰對相同的資料進行3次加密，安全性更高

4. RC系列-RC4
    > symmetric key stream cipher
    > 串流加密
5. RC系列-RC5
    > parameterized algorithm 
    > 區塊加密
6. RC系列-RC6
    > 使用RC5加上整數乘法，並實現4個4位工作暫存器，而不是RC5的2個2位暫存器
7. Blowfish
    > Blowfish is a type of symmetric block cipher algorithm designed to replace DES or IDEA algorithms

8. Twofish and Threefish 
    :::danger
    考試會考
    :::
    - Twofish
        > **block size of 128 bits and key size up to 256bit**
    -  Threefish
        - It is a large tweakable symmetric-key block cipher in which the block and key sizes are equal, i.e., 256, 512, and 1024.
        - Addition-Rotation-XOR (ARX)

9. Serpent
    - 對稱式分組加密演算法
    > 128 bit symmetric block cipher
10. TEA
    - 微型加密演算法（Tiny Encryption Algorithm，TEA）
    > Feistel cipher - 費斯妥密碼 常用在分組加密演算法中
    > 128 bit key and 64 bit blocks
    > 232/the golden ratio

11. CAST-128
    > CAST-128, also called CAST5, is a symmetric-key block cipher having a classical 12-or 16-round Feistel network with a block size of 64 bits. 

12. GOST Block Cipher 
    > also called Magma
    > 32-round Feistel network

13. Camellia
    > Camellia is a symmetric-key block cipher having either 18 rounds (for 128-bit keys) or 24 rounds (for 256-bit keys).

### Asymmetric-key algorithms (Public-key cryptography)
- 非對稱式加密(公鑰)
- 技術: RSA、DSA、ECC、Diffie-Hellman、El Gamal

1. DSA
    > DSA (Digital Signature Algorithm)
    > DSA 的一個重要特點是兩個質數公開，這樣，當使用別人的公鑰時，即使不知道私鑰，你也能確認它們是否是隨機產生的，還是作了手腳，RSA 算法卻作不到。

2. RSA
    > RSA(Rivest Shamir Adleman)
    > 發明者的名字命名，公鑰和私鑰都是兩個大質數的函數

3. Diffie-Hellman(DH)
    > It is a cryptographic protocol that allows two parties to establish a shared key over an insecure channel.
    > 允許兩名用戶在公開媒體上交換資料以生成"一致"的、可以共享的密鑰。換句話說，就是由甲方產出一對密鑰（公鑰、私鑰），乙方依照甲方公鑰產生乙方密鑰對（公鑰、私鑰）。以此為基準，作為數據傳輸保密基礎，同時雙方使用同一種對稱加密算法構建本地密鑰（SecretKey）對數據加密。這樣，在互通了本地密鑰（SecretKey）算法後，甲乙雙方公開自己的公鑰，使用對方的公鑰和剛才產生的私鑰加密數據，同時可以使用對方的公鑰和自己的私鑰對資料解密。不單單是甲乙雙方兩方，可以擴展為多方共享數據通訊

4. YAK
    > YAK is a public-key-based Authenticated Key Exchange (AKE) protocol. The authentication of YAK is based on public key pairs, and it needs PKI to distribute authentic public keys

### HASH
- 技術: HAVAL、SHA、SHA-1、HMAC、HMAC-MD5、HMAC-SHA1
1. MD系列
    - 單向雜湊函數(one way hash function)：MD2、MD4、MD5  
    - 接收任意長度的位元組，並產生唯一的固定長度(128 bit)，這個過程是單向的不能再由簽名反向產生訊息，並且其數質是唯一的。

2. SHA系列
    - SHA-1
        - 160 bits digest
    - SHA-2
        - ex: sha-256, 32-bits words 
        - ex: sha-512, 64-bits words
    - SHA-3
        - 太新 沒地方好用


### Other Encrpytion Techniques
1. Elliptic Curve Cryption 
    > 橢圓密碼曲線，ECC
2. Quantum Cryption
    > 量子加密
    > Quantum key distribution (QKD)
3. Homomorphic Encrpytion
    > 同態加密
    > 不需要解密就可以直接運算
    > 雲端時代下的趨勢
### Hardware-Based Encryption
> 硬體式加密
1. TPM
2. HSM
3. USB Encrpytion

### Public Key Infrastructure(PKI)
> 公開金鑰密碼
> 打造一個可以安全使用公鑰加密的環境

> PKI is a set of hardware, software, people, policies, and procedures required to create, manage, distribute, use ,store, and revoke, digitial certificate.

#### Digital Signature
- Sign -> Seal -> Deliver
- Accept -> open -> vertify

## Crytanalysis
### Brithday attack
> 打雜湊 不同訊息同雜湊
>  birthday attack refers to a class of brute-force attacks against cryptographic hashes that renders brute-forcing easier to performs.
#### Brithday Paradox: Probility 
> 生日謬論
> 生日問題是指最少需要幾人，當中的兩個人生日相同的機率才會大於50%。這個題目的答案是23人。 這就意味著在一個典型的標準小學班級（30人）中，存在兩人生日相同的可能性更高。對於60或者更多的人，這種機率會大於99%。這個問題有時也被稱做生日悖論，但從引起邏輯矛盾的角度來說生日悖論並不是一種悖論，它被稱作悖論只是因為這個數學事實與一般直覺相牴觸而已。大多數人會認為，23人中有2人生日相同的機率應該遠遠小於50%。計算與此相關的機率被稱為生日問題，在這個問題之後的數學理論已被用於設計著名的密碼攻擊方法：生日攻擊。

### Meet-in-the-Middle Attack 
> 中途攻擊
> 目的：打數位簽章，藉以取明文與密文之間的變化去取得演算法的內容
-   舉例來說，像說丟不同的變數或字典檔，回覆的內容也會不同，籍以猜測真正的密碼


### Side-Channel Attack 
> 旁道攻擊
> 目的: 時間資訊、功率消耗、電磁泄露或是聲音頻率均可以提供額外的資訊來源，可被利用於進一步對系統的破解
- ex: 聽CPU聲音破解4096 RSA
- ex: 實體攻擊(Physical attack)，如砸鎖
- ex: 舉例來說，以偷取信用卡的讀卡機來說，詐騙集團可以透過極近的距離，取得電子簽證的信用卡號及驗證碼

### Hash Collision Attack
> A hash collision attack is performed by finding two different input messages that result in the same hash output. 

### DUHK Attack
> don't use hard-coded keys (DUHK)
> 密碼寫在程式碼裡

### Related-Key Attack
> 用數學基礎做破解，代表加密演算法不夠好

### Padding Oracle Attack
> also known as Vaudeny attack
> 在加密學中，密文填塞攻擊（Padding Oracle attack，字面譯為填充神諭攻擊）是指使用密文的填充驗證資訊來進行解密的攻擊方法。密碼學中，可變長度的明文資訊通常需要經填充後才能相容基礎的密碼原語。此攻擊方式依賴對密文是否被正確填充的回饋資訊。密文填塞攻擊常常與區塊加密法內的密碼塊連結解密模式有關。非對稱加密演算法，如最佳非對稱加密填充演算法，也可能易受到密文填充攻擊。
- 有些加密法會填充字串到特定長度，透過嘗試測出填充規則後就可破解
### Drown Attack 
:::danger
考試會考
:::

> 降防攻擊(跨協定攻擊)
> Decrypting RSA with Obsolete and Weakened eNcryption(DROWN)

> 解釋1: 指的是破解基於老舊及脆弱加密的RSA演算法，駭客利用特製的連結存取SSLv2伺服器就能截取並解密TLS流量
> 解釋2: 這類的攻擊透過SSLv2協定漏洞去攻擊採用TLS協定的安全連結，雖然SSLv2與TLS皆支援RSA加密，但TLS能夠防禦針對RSA加密的攻擊，SSLv2則否

> 過程: 駭客反覆地連結被鎖定的SSLv2伺服器並傳送特製的交握（handshake）訊息，並變更客戶端連結的RSA密文，在不斷地試探下，伺服器終將洩露客戶端TLS連結所使用的金鑰。


:::info
### Key Points
1. PDKDSF2
    - 不可抵抗硬體破解
    > PBKDF2 演算法是一種實現 密鑰延伸(key stretching) 類型的演算法，這類型的演算法是為了對抗電腦運算速度太快，避免密碼被暴力破解的解決方案。
    > PBKDF2會先使用 hash 類型的演算法，將 hash 的結果當成hash 演算的鹽，重新再跑一次 hash，反覆遞迴運算。
    > 因此只要將遞迴 hash 的次數調升，就可以輕鬆地讓運算速度降低，減緩運算速度快的破解時間。
2. Bcrypt
    - 能對抗硬體加密的演算法
    > 實作中bcrypt會使用一個加鹽的流程以防禦彩虹表攻擊，同時bcrypt還是適應性函式，它可以藉由增加疊代之次數來抵禦日益增進的電腦運算能力透過暴力法破解。
    > 除了對資料進行加密，預設情況下，bcrypt在刪除資料之前將使用隨機資料三次覆蓋原始輸入檔案，以阻撓可能會獲得電腦資料的人恢復資料的嘗試。
:::

