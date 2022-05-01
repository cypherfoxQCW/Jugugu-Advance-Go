package main

/*
 * @Descripttion:封装密钥托管的引用例子
 * @version:0.1
 * @Author: 秦风大哥
 * @Date: 2022-01-21 17:58:30
 * @LastEditors: 秦风大哥
 * @LastEditTime: 2022-01-21 18:04:46
 */

import (
	"fmt"

	bcc "github.com/cypherfoxQCW/Jugugu-Advance-Go"
)

func main() {
	bcc.InitRSAPuk("globlepublic.pem")
	body, err := bcc.UserNFTsPost(bcc.TestIPandPort, "CFX_UserNFTs", bcc.ERC155牛项目AAPID, bcc.TestCFXAdministratorAddress, "UserNFTsPost", "cfx")
	if err != nil {
		panic(err)
	} else {
		fmt.Println(string(body))
	}
	多次批量创建NFT(-1)
}
func 多次批量创建NFT(i int64) {
	var tos []string
	tos = append(tos, "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0")
	tos = append(tos, "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0")
	tos = append(tos, "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0")
	tos = append(tos, "cfxtest:aakmdj7tutgdy3h558rr5621mhrrx75kfyw3e3sfz0")
	tos = append(tos, "cfxtest:aat4818p1b264d91e5xy31cthyn3thbnx2ect50gr3")
	body, err := bcc.AdminCreateNFTBatchPost(bcc.TestIPandPort, "CFX_AdminCreateNFTBatch", bcc.ERC155牛项目AAPID, i, 50000, bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, tos, "CFX_AdminCreateNFTBatch", "cfx")
	if err != nil {
		panic(err)
	} else {
		fmt.Println(string(body))
	}
	//1155转移请将action设置为：CFX_1155TransferFrom
	//721转移请将action设置为：CFX_TransferFrom
	body, err = bcc.TransferFromPost(bcc.TestIPandPort, "CFX_1155TransferFrom", bcc.ERC155牛项目AAPID, -1, 50000,
		bcc.TestAdministratorPassword, bcc.TestCFXAdministratorAddress, "cfxtest:aat4818p1b264d91e5xy31cthyn3thbnx2ect50gr3", "278", "CFX_1155TransferFrom", "cfx")
	if err != nil {
		panic(err)
	} else {
		fmt.Println(string(body))
	}
}
