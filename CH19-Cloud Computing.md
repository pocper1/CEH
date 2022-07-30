{%hackmd @themes/notion %}

###### tags: `資訊安全`

# CH19-Cloud Computing
| 事項         | 時間                              |
| ------------ | --------------------------------- |
| 上課日期     | 2022/06/25(六) 09:00 ~ 18:00      |
| 最後更新日期 | 2022/07/31(日) 01:35              |
| 編輯人       | @pocper1、@2CwPgtM-RUuet4CyKo4Xmw |

## 文章
### 目錄
[TOC]

### 概要
> 了解雲端環境安全
---

## Cloud Computing Concepts
### Introduction to Cloud Computing
> Cloud computing is an on-demand delivery of IT capabilities, in which IT infrastructure and applications are provided to subscribers as metered services over networks. Examples of cloud solutions include Gmail, Facebook, Dropbox, and Salesforce.com.

### Characteristics of Cloud Computing
> cloud 五大特質
- on-demend self-service
    - ex. 下午三點訂餐
- broad network access
    - ex. 想訂什麼就訂什麼
- Resource pooling
- rapid elasticity
    - ex. 呼之則來 呼之則去
- Measured service
    - ex. 用多少付多少

### Types of Cloud Computing Services
- infrasture-as-a-service (Iaas)
    - 虛擬機
- Platform-as-a-service (Paas)
    - 平台API
- Software-as-a-service (Saas)
    - 現存的軟體應用程式
    - ex: google fb 
    <img src="https://chtseng.files.wordpress.com/2014/05/image0033.png" />

### Cloud Deployment Models
- Public cloud
    > In this model, the provider makes services such as applications, servers, and data storage available to the public over the Internet
- private cloud
    - virtual private cloud 
    - ex:amazon google
- community cloud
    > It is a multi-tenant infrastructure shared among organizations from a specific community with common computing concerns, such as security, regulatory compliance, performance requirements, and jurisdiction.
- hybrid cloud
    > It is a cloud environment comprised of two or more clouds (private, public, or community) that remain unique entities but are bound together to offer the benefits of multiple deployment models.
    - 混和雲
- multi cloud
    > It is a dynamic heterogeneous environment that combines workloads across multiple cloud vendors that are managed via one proprietary interface to achieve long-term business goals.
    - 由多個雲組成 避免當機
    <img src="http://i2.kknews.cc/zV6SXz3hLeXi4gF39p15EX9SApqilrMSz16Xd-Q/0.jpg" />

## Container Technology
:::danger
考試會考
:::
### Container Technology Architecture

> As shown in the below figure, container technology has a five-tier architecture and undergoes a three-phase lifecycle: 
- Tier-1: **Developer machines** 
    - image creation, testing and accreditation 
- Tier-2: **Testing and accreditation systems** 
    - verification and validation of image contents, signing images and sending them to the registries
- Tier-3: **Registries** 
    - storing images and disseminating images to the orchestrators based on requests
- Tier-4: **Orchestrators** 
    - transforming images into containers and deploying containers to hosts
- Tier-5: **Hosts** 
    - operating and managing containers as instructed by the orchestrator

### What is a Container
- a container is a package of an application/software including all its such library file, config files, binaries and other resourses that run independently of other processes in the cloud environment
沙箱(效果差)、虛機(所需資源多)
- orchestrator 協調器


### Container v.s. Virtual Machines
<img src="https://www.netapp.com/media/Screen-Shot-2018-03-20-at-9.24.09-AM_tcm19-56643.png?v=85344" />


| VM                                      | Container                                                       |
| --------------------------------------- | --------------------------------------------------------------- |
| 每個虛機有自己的作業系統                | 執行在Container Engine                                          |
| 以作業系統為單位                        | 以應用程式為單位                                                |
|                                         | 依賴Host OS的核心(kernel)來運行Container                        |
| 是一個配置好CPU、RAM與Storage的作業系統 | 一個封裝了相依性資源與應用程式的執行環境                        |
| VM則會因版本不同造成環境的衝突          | Container間是彼此隔離的，同一台機器我們可以執行不同的版本的服務 |
| Container多使用於微服務                 | VM使用較大型的服務                                              |


| Virtual Machines                          | Container                                  |
| ----------------------------------------- | ------------------------------------------ |
| Heavyweight                               | Lightweight and portable                   |
| Run on independent operating systems      | Share a single host operating system       |
| Hardware-based virtualization             | OS-based virtualization                    |
| Slower provisioning                       | Scalable and real-time provisioning        |
| Limited performance                       | Native performance                         |
| Completely isolated making it more secure | Process-level isolation, partially secured |
| Created and launched in minutes           | Created and launched in seconds            |

 
### What is Docker
> Docker is an open-source technology used for developing, packaging, and running applications. 

#### Docker Architecture
- Docker Daemon
    - The Docker daemon (dockerd) processes the API requests and handles various Docker objects, such as containers, volumes, images, and networks.
- Docker Client
    - It is the primary interface through which users communicate with Docker. When commands such as docker run are initiated, the client passes related commands to dockerd, which then executes them. Docker commands use the Docker API for communication.
- Docker Registries
    - Docker registries are locations where images are stored and pulled, and can be either private or public. Docker Cloud and Docker Hub are two popular public registries. Docker Hub is a predefined location of Docker images, which can be used by all users.
- Docker Objects
    - Docker objects are used to assemble an application. The most important Docker objects are as follows: 
        - Images: Images are used to store and deploy containers. They are read-only binary templates with instructions for container creation.
        - Containers: Application resources run inside the containers. A container is a runnable instance of an application image. Docker CLI or API is used to create, launch, stop, and destroy these containers.
        - Services: Services enable users to extend the number of containers across daemons, and together they serve as a swarm with several managers and workers. Each swarm member is a daemon, and all these daemons can interact with each other using Docker API.
        - Networking: It is a channel through which all isolated containers communicate.
        - Volumes: It is a storage where persisting data created by Docker and used by Docker containers are stored.

### Microservices v.s. Docker
<img src="https://boosthigh.com/wp-content/uploads/2019/08/Monolithic-Architecture-1.jpg" />


### Docker Networking
Docker native Network
Container Network Model(CMM)
- 以下將會介紹目前 docker 預設支援的網路類型，包含：

1. bridge
2. host
3. overlay
4. macvlan
5. none
![](https://i.imgur.com/LWt5Lio.png =80%x)

### What is kubernetes (K8s)
- google開發的 最有名的協調器
- 用來管理容器

### Container Security Challenges
- 資料速度
- 安全

## Serverless Computing
- 無伺服器運算（英語：Serverless computing），又被稱為功能即服務（Function-as-a-Service，縮寫為 FaaS），是雲端運算的一種模型。以平台即服務（PaaS）為基礎，無伺服器運算提供一個微型的架構，終端客戶不需要部署、組態或管理伺服器服務，程式碼運行所需要的伺服器服務皆由雲端平台來提供。
<img src="https://cdn2.hubspot.net/hubfs/5129222/Imported_Blog_Media/serverless-architecture-590x474-1.png" />

## OWASP Top 10 Cloud Security Risks
- R1 Accountability and Data Ownership
- R2 User Identity Federation
- R3 Regulatory Compliance
- R4 Business Continuity and Resiliency
- R5 User Privacy and Secondary Usage of Data
- R6 Service and Data Integration
- R7 Multi Tenancy and Security
- R8 Incidence Analysis and Forensic Support
- R9 Infrastructure Security
- R10 Non-Production Environment Exposure

## Cloud Attacks
### Man-in-the-cloud(MITC) Attack
> MITC attacks are an advanced version of MITM attacks. 
> In MITM attacks, an attacker uses an exploit that intercepts and manipulates the communication between two parties, while MITC attacks are carried out by abusing cloud file synchronization services, such as Google Drive or DropBox, for data compromise, command and control (C&C), data exfiltration, and remote access. Synchronization tokens are used for application authentication in the cloud but cannot distinguish malicious traffic from normal traffic. Attackers abuse this weakness in cloud accounts to perform MITC attacks.

### cloud Hopper Attack
> 雲端哈播攻擊
- 目的: 從雲端服務打進提供服務的廠商 之後再用廠商的權限搞下面的機器
    > Once the attack is successfully implemented, attackers can gain remote access to the intellectual property and critical information of the target MSP and its global users/customers. Attackers also move laterally in the network from one system to another in the cloud environment to gain further access to sensitive data pertaining to the industrial entities, such as manufacturing, government bodies, healthcare, and finance.

- 攻擊過程
    1. Attackers initiate **spear-phishing emails** with custom-made malware to compromise user accounts of staff members or cloud service firms to obtain confidential information. 
    2. Attackers can also use PowerShell and PowerSploit command-based scripting for reconnaissance and information gathering. 
    3. Attackers use the gathered information for accessing other systems connected to the same network. 
    4. To perform this attack, attackers also leverage C&C to sites spoofing legitimate domains and file-less malware that resides and executes from memory. 
    5. Attackers breach the security mechanisms impersonating a valid service provider and gain complete access to corporate data of the enterprise and connected customers.

### Cloud Cryptojacking
> 用雲端算比特幣

- 時事: [bloomberg chinese motherboard](https://www.bloomberg.com/features/2021-supermicro/)

### Enumerating S3 Bukets
- Inspecting  HTML
- Brute-forcing URL
- Finding subdomains
- Reverse IP Search
- Advanced Google Hacking

#### CloudGoat AWS
- 可以架設有問題的amazon環境 進行測試












