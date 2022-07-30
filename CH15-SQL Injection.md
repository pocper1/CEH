{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH15-SQL Injection
| 事項         | 時間                             |
| ------------ | -------------------------------- |
| 上課日期     | 2022/05/29(日) 09:00 ~ 18:00     |
| 最後更新日期 | 2022/07/31(日) 01:35             |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 了解SQL 注入攻擊方式及種類
---

- https://ithelp.ithome.com.tw/articles/10240102
## authorization bypass
> 密碼注入攻擊
- 工具:sqlmap
 
1. 單行註解
    - username: Blah' or 1=1--
    - password: Springfield
    ```sql=
    SELECT Count(*) FROM Users WHERE UserName='Blah' or 1=1 --' AND Password=' Springfield';
    ```
    ```sql+
    # 解釋 -- -- 代表單行註解
    Blah' or 1=1 -- --
    ```
    - 可以用單引號註解掉並且用or 達到accept
    - 萬用密碼注入攻擊 qwe'OR 1==1
2. OR == 攻擊
    ```bash=
    sqlmap --url='www...'  --cookie='(session)'
    ```
    ==註解: (Seesion)(從f12找)==

### Information Disclosure
> 目的：可以看到db的table
```bash=
/--dbs/ /-D --table/ /-D ? -T ? --columns
```

1. Union based SQL injection
2. Stacked based SQL injection
3. Boolean based SQL injection


## Types of SQL Injection
- In-band SQL Injection
- Blind/Inferential SQL Injection
- Out-of-Band SQL Injection

### In-Band SQL Injection
> 在same communication channel retrieve the results
> 在同個網頁，撈出錯誤資料
- Error-based SQL injection 
- System Stored Procedure
- Illegal/Logically IncorrectQuery
- Union SQL injection
- Tautology
- End of Line Comment
- In-line Comments
- Piggybacked Query

### Blind/Inferential SQL Injection
> 系統不會有明確的錯誤訊息，鑰靠觀察伺服器有沒有回應，
> 透過True或False的方式來判斷SQL語法是不是有用

1. No Error Message Returned
2. WAITFOR DELAY (YES or NO Response)
3. Boolean Exploitation 
4. Time-insentive(Heavy Query)

### Out-of-Band SQL Injection (OOB)
- 透過某個進入點打你，但是用另一個點拿資料
- 最有效率的攻擊方法
- 缺點:風險高 很難達成
> Attackers use DNS and HTTP requests to retrieve data from the database server. For example, in Microsoft SQL Server, an attacker exploits the xp_dirtree command to send DNS requests to a server controlled by the attacker. Similarly, in Oracle Database, an attacker may use the UTL_HTTP package to send HTTP requests from SQL or PL/SQL to a server controlled by the attacker.

1. communicate with the server
2. communication channels
3. DNS and HTTP requests
4. xp_dirtree command

## SQL Injection Methodology
- tools: burp suite
### Information Gathering
1. Database server
2. input fields, hidden fields
3. inject codes
4. string value
5. UNION operator
6. error messages
### Launch SQL Injection Attacks
#### Perform Union SQL Injection
1. Extract Database Name
2. Extract Database Table
3. Extract Table Column Names
4. Extract 1st Field Data
- bool if 高機率blind sql injection

### Interacting with the Operating System
> 透過SQL injection 可以執行shell
:::info
常用工具: xp_cmdshell command
:::
```bash=
sudo nc -nvlp21
```
==以上為執行後門指令==

```shell=
twist3 ftp --help
```
- 攻擊者常常只有一次enter的機會，所以會看到一長串的程式碼

attacker: nc -nvlp8008
- 找web.config 裡面可能有資料庫帳號

- 提權工具 [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
### Interaction with the file system
1. load_file()
    - 抓取任意檔案
2. INTO outfile()

### Evasion Techniques
1. In-line comment
    - 透過/* */ 或者 -- 
2. CharEncoding
    - 多用Ascii code
3. String Concatenation
    - 字串串接 
4. Obfuscated Code
    - 混淆式
5. Manipulating White Spaces
    - dropping or adding white spaces
    - 多加空白或或者少空白
6. Hex Encoding
    - 相容性很好
    - hex encoding to string
7. Sophisticated Matches
    - 1==1 -> 'abc' == 'a'+'bc'
8. URL Encoding
    - hex form preceding each code point with a pecent sign '%'
9. Null Byte
    - %00
    - 塞入空字元=>NULL
10. Case Variation
    - 大小寫變換法
## CH15 Practice
1. [Lab1-2] Perform an SQL Injection Attack Against MSSQL to Extract Databases using sqlmap
