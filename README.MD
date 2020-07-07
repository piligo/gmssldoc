# 国密SSL 交互过程详细分析

https://github.com/piligo/gmssldoc



## 前言

1、国密tls/ssl库 go语言 https://github.com/piligo/gmtls

2、国密tls/ssl库的交互过程详细分析：https://github.com/piligo/gmssldoc

3、国密tls/ssl库的使用样例： https://github.com/piligo/gmssl-sample

## 编译命令

0、gmtls 封装好的国密的ssl 库纯golang的

```
git clone https://github.com/piligo/gmtls.git
```

备注：

使用样例
参考 example/client_gmtls.go 和 example/server_gmtls
或者 参考项目：https://github.com/piligo/gmssl-sample.git



1、gmsm 国密相关实现库，此库是https://github.com/tjfoc (同济库开源修改过来的)

```
git clone https://github.com/piligo/gmsm.git
```

2、gmssldoc

```shell
git clone https://github.com/piligo/gmssldoc.git
#编译所有测试命令
make
#或者编译单独的
go build -mod=vendor cmd/Certificates.go

#生成的目录执行相关命令即可
```

```
Certificates --证书的读写测试
ClientFinished --clientFinished 校验位计算测试
ClientKeyExchange  --keyExchange 的计算过程
MasterSecret   --主秘钥的计算过程
ServerFinished --Server端的Finished计算过程
ServerKeyExchange --keyExchange的计算过程
```

```
国密SSL交互的过程.Md 详细的算法计算过程和说明
TASSL环境准备.md  --使用TASSL的库来做环境校验
```

3、gmssl-sample

```shell
git clone https://github.com/piligo/gmssl-sample.git
#编译所有测试命令
make
#或者编译单独的
go build -mod=vendor cmd/client_gmtls.go
go build -mod=vendor cmd/server_gmtls.go

#启动客户端和服务端，即可看到交互的过程。
#注意 server_gmtls 依赖当前目录下sm2Certs 的相关证书（证书的生成参考 https://github.com/piligo/gmssldoc 项目中的TASSL环境准备文档）
./server_gmtls 
./client_gmtls 即可
```

```
也可以使用TASSL 命令作为客户端或者服务端 与 server_gmtls /client_gmtls 进行通信验证。
测试也可以通过
```

