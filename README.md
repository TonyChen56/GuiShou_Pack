# GuiShou_Pack

使用C ++控制台实现的加壳器

# 使用须知

1. 打开main.cpp
2. 修改要加壳目标程序路径 char path [MAX_PATH] =“E：\ FileCleaner2.0.exe”必须是绝对路径。
3. 拉到main函数最下面 修改保存被加壳的程序路径
4. 兼容性不是很高 可能会有bug

# 实现功能

1. 增加区段 能够向目标程序添加代码 
2. AES加密所有段
3. 密码弹框 
4. TLS处理    
5. 花指令混淆
6. PEB反调试
7. IAT加密                                  

# 160的crackme

从第一个开始尽量对每个的crackme进行逐个的分析

每个的crackme为一个单独的文件夹

文件夹里有以下内容

1. 对程序的详细的分析过程 (md格式和pdf格式) 如果下载md格式必须和assert文件夹一起下载(之前是用的微博图床存放图片，后来感觉不靠谱 006开始就用的本地文件夹)（markdown格式可下载Typora查看）
2. UDD文件
3. 源目标程序和目标程序运行所需的dll
4. 破解后的程序

最后附上自己的CSDN博客:https://blog.csdn.net/qq_38474570 求关注 点赞 收藏
