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

