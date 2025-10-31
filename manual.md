# S-AES加密系统用户手册

## 系统概述

S-AES加密系统是一个基于简化版高级加密标准（Simplified AES）的加密工具，提供了多种加密模式和功能。该系统采用图形化界面，支持16位数据的加密解密操作。

## 系统要求

- Python 3.6或更高版本
- tkinter库（通常随Python一起安装）

## 安装和运行

1. 确保已安装Python 3.6+
2. 将代码保存为`s_aes_gui.py`
3. 在命令行中运行：`python s_aes_gui.py`

## 功能模块详解

### 16进制字符加密

- **功能描述**：基础的S-AES加密解密功能测试

- **操作步骤**：
  1. 在"明文"字段输入16位十六进制数字（如：1234）
  2. 在"密钥"字段输入16位十六进制数字（如：5678）
  3. 点击"加密"按钮进行加密操作
  4. 查看下方输出区域的加密结果
  5. 点击"解密"按钮验证解密功能
  6. 点击"清空"按钮清除输出内容

- **注意事项**：
  - 所有输入必须是有效的16位十六进制数字
  - 明文的长度应为4个十六进制字符（16位）
- <img width="683" height="496" alt="image" src="https://github.com/user-attachments/assets/3162e9ef-f8f4-4933-9f41-4ca536450299" />
- <img width="695" height="446" alt="image" src="https://github.com/user-attachments/assets/e7454459-2a43-49f3-b07c-306fd28ce6e2" />



### ASCII字符加密

- **功能描述**：支持ASCII字符串的加密和解密

- **操作步骤**：
  1. 在"ASCII字符串"字段输入要加密的文本（如：Hello world!）
  2. 在"密钥"字段输入16位十六进制数字（如：ABCD）
  3. 点击"ASCII加密"进行加密
  4. 查看加密后的块数据和可能的乱码文本
  5. 点击"ASCII解密"验证解密功能

- **注意事项**：
  - 加密后的文本可能包含不可显示字符，会显示为乱码
  - ASCII加密与基础模式加密结果不同，因为输入数据表示方式不同
- <img width="619" height="593" alt="image" src="https://github.com/user-attachments/assets/1a0f730b-533c-48e1-8d6e-9e8ac5be3182" />
- <img width="624" height="541" alt="image" src="https://github.com/user-attachments/assets/4798b516-2112-4a2e-adb4-45fe7819cc7e" />



### 双重加密

- **功能描述**：使用两个16位密钥进行双重加密，提供更强的安全性

- **操作步骤**：
  1. 在"明文"字段输入16位十六进制数字
  2. 在"密钥"字段输入32位十六进制数字（两个16位密钥）
  3. 点击"双重加密"进行加密
  4. 点击"双重解密"进行解密
- <img width="632" height="594" alt="image" src="https://github.com/user-attachments/assets/9606b536-d811-4fda-81ef-0fc4dda72b32" />
- <img width="624" height="590" alt="image" src="https://github.com/user-attachments/assets/df18fae2-675b-473a-8877-538f519e029b" />



### 中间相遇攻击

- **功能描述**：演示针对双重加密的中间相遇攻击

-  **操作步骤**：
   1. 在文本框中输入多组明密文对，每行一组，格式为"明文,密文"
   2. 点击"执行中间相遇攻击"
   3. 查看攻击结果，系统会尝试找出可能的密钥对

- **示例输入**：
```
1234,B74B
5678,E665
9ABC,0878
```
- <img width="1002" height="915" alt="image" src="https://github.com/user-attachments/assets/e5b95eb2-5b1d-4fdf-a8d7-aa34427239a4" />


### 三重加密

- **功能描述**：使用EDE模式进行三重加密

- **操作步骤**：
  1. 在"明文"字段输入16位十六进制数字
  2. 在"密钥"字段输入32位十六进制数字
  3. 点击"EDE模式加密"进行加密
  4. 点击"EDE模式解密"进行解密
- <img width="625" height="604" alt="image" src="https://github.com/user-attachments/assets/eff84352-f127-42f6-abd2-2b63d4820670" />
- <img width="623" height="596" alt="image" src="https://github.com/user-attachments/assets/fccfa900-5da4-406d-84cd-0b221de55b98" />



### CBC模式

- **功能描述**：使用密码分组链接模式进行加密，提供更好的安全性

- **加密操作**：
  1. 选择输入类型（十六进制或文本）
  2. 在"数据"字段输入要加密的内容
     - 十六进制模式：输入十六进制字符串（如：1234ABCD）
     - 文本模式：输入普通文本（如：Hello World!）
  3. 在"密钥"字段输入16位十六进制数字（如：5678）
  4. 在"初始向量IV"字段输入16位十六进制数字（可选，如：9ABC）
  5. 点击"CBC加密"进行加密
  6. 复制"完整密文"用于解密
     
- **解密操作**：
  1. 将加密得到的"完整密文"粘贴到"数据"字段
  2. 输入相同的密钥
  3. IV字段可以留空（IV已包含在密文中）
  4. 点击"CBC解密"进行解密
    
- 16进制加解密
- <img width="749" height="598" alt="image" src="https://github.com/user-attachments/assets/5728f0b3-f083-4d2d-9203-d5960d144f53" />
- <img width="749" height="598" alt="image" src="https://github.com/user-attachments/assets/8014682e-b3c0-4bca-a154-1581702cbb39" />

- 文本加解密
- <img width="747" height="638" alt="image" src="https://github.com/user-attachments/assets/bdfaf20a-2e2a-485b-9f1d-79679d24643a" />
- <img width="746" height="564" alt="image" src="https://github.com/user-attachments/assets/a46252b4-f5f6-40e1-af33-64e0d181d72d" />

- **篡改测试**：
  1. 点击"篡改测试"演示CBC模式下数据篡改的影响
  2. 观察错误传播特性
- <img width="749" height="640" alt="image" src="https://github.com/user-attachments/assets/ca5af3e4-5403-4e1a-bbc4-ab6507b15a69" />


- **生成示例**：
  1. 点击"生成示例"查看详细的使用示例和说明
- <img width="1002" height="915" alt="image" src="https://github.com/user-attachments/assets/5d9eeaae-25a9-42ee-885c-5657c83bd385" />


## 技术细节

### 加密算法特点

- **S-AES算法**：简化版AES，使用16位数据和16位密钥
- **轮数**：2轮加密
- **操作**：包括字节替换、行移位、列混淆和轮密钥加

### 工作模式

1. **ECB模式**：基本加密模式，每个块独立加密
2. **CBC模式**：密码分组链接模式，每个密文块依赖于前一个块

## 使用技巧

1. **文本加密**：对于文本数据，使用文本输入模式，系统会自动处理编码和填充
2. **十六进制加密**：对于原始字节数据，使用十六进制输入模式
3. **IV选择**：对于安全性要求高的场景，建议使用随机IV
4. **验证结果**：加解密后，检查输出中的字节信息，确认数据处理正确

## 安全提示

1. 本系统为教学演示工具，不建议用于生产环境的敏感数据加密
2. S-AES是简化版算法，安全性低于标准AES
4. 多重加密可以提供更高的安全性，但也会增加计算复杂度
5. CBC模式中，IV应该是随机且不可预测的

## 故障排除

1. **程序无法启动**：检查Python版本和tkinter库是否正确安装
2. **加密解密结果不正确**：确认输入格式正确，特别是十六进制数字
3. **界面显示异常**：尝试调整窗口大小或检查系统显示设置
4. **CBC解密失败**：确保使用完整的密文（包含IV），且密钥正确

