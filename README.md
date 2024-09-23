# 介绍
这是将天玄区块链中的一些通用功能抽离出来实现的一个通用模块，如签名相关功能等。不论是天玄节点应用服务和网关还是天玄 web3j sdk 都依赖于此模块。

# 编译
拉取仓库后，进入文件夹，执行下面指令
```sh
mvn clean install -Dmaven.test.skip=true
```
指令执行成功后，会在 `target` 文件夹内产生 `thanos-common.jar` 文件。

# 教程
打包编译教程：
* [在线文档 - 打包可执行文件](https://tianxuan.blockchain.163.com/installation-manual/tianxaun-chain/executable-file.html)
* [文档仓库 - 打包可执行文件](https://github.com/TianXuan-Chain/tianxuan-docs/blob/new-pages/tools/blockchain-browser/installation-manual/tianxaun-chain/executable-file.md)

# License
Apache 2.0
