# blockchaincommon-go-sdk
Fragment storage key escrow system supported by the whole chain
全链支持的密钥托管系统接口go-SDK
内附带测试常量，可以直接测试
函数带有详细使用规则
目前业务只需要使用掌握：Reg、TotalSupplyPost、UserNFTsPost、AdminCreateNFTPost、AdminCreateNFTBatchPost、AdminTransferNFTBatchPost、TransferFromPost
其他的后续掌握也可以


##### 2022.03.11  注意ERC721和ERC1155的TransferFrom函数的actionName的不同传参
##### 2022.03.11  AdminCreateNFTBatchPost新增加返回json数据格式，包含hash和ID以及该ID的所有者地址，格式如下：
```
{
    "hash": "0x7cc4898aa8b1b4e7a5deb6fa0b16c35df2665402e6cf176d27f6ff70f9e99d76",
    "nfts": [
        {
            "id": "208",
            "owner": "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0"
        },
        {
            "id": "209",
            "owner": "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0"
        },
        {
            "id": "210",
            "owner": "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0"
        },
        {
            "id": "211",
            "owner": "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0"
        },
        {
            "id": "212",
            "owner": "cfxtest:aat4818p1b264d91e5xy31cthyn3thbnx2ect50gr3"
        }
    ]
}
```


## 2022.04.10 新增新的hash算法，优化RSA加密，提升效率

## 2022.04.12 新增公用的HTTPS服务器
## 2022.04.13 修复管理员地址错误问题
