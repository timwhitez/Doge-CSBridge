# Doge-CSBridge
CS http Dynamic Encrypt Bridge.

- 🐸Frog For Automatic Scan

- 🐶Doge For Defense Evasion&Offensive Security

- 本系列命名为Frog可能是因为这种生物的寿命长 🐸 🤓 +1s 

- Frog-Fp为Frog系列第三个项目🐸，写的有点累了

- 安全本逆天而行，猝死很正常，请勿用作授权之外非法用途

## 0x00 引

流量层面的对抗处于地位，而Cobalt Strike的profile配置文件虽然给予了使用者很大的灵活性去做流量混淆，但仍然会存在特征。

前段时间和朋友聊到了流量加密

是否存在一种较为简单的方式，能够满足在不传递密钥的情况下，客户端与服务端动态密钥的同步生成，以及丢包不影响密钥的同步。

## 0x01 构思

结合上述，联想到了前段时间做的golang对接Google Authenticator，将OTP验证码作为对称加密密钥是一种可行的方案。整体的方案规划如下：

- Cobalt Strike Beacon挂本地的proxy加密外连
- server端收到Beacon的加密数据后解密并传给teamserver
- teamserver处理产生response给server
- server加密response发送给beacon
- beacon的proxy将response解密
- proxy和server都内置otp初始secret密钥

整体架构如下图：

![image](https://user-images.githubusercontent.com/36320909/141474352-32bf7ee7-2391-4f0c-8b77-fee42e637aed.png)


具体实现细节见代码不赘述。

仅为概念验证项目。
