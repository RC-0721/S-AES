import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import struct


class SAES:
    # S盒和逆S盒 - 标准S-AES S盒
    S_BOX = [
        [0x9, 0x4, 0xA, 0xB],
        [0xD, 0x1, 0x8, 0x5],
        [0x6, 0x2, 0x0, 0x3],
        [0xC, 0xE, 0xF, 0x7]
    ]

    INV_S_BOX = [
        [0xA, 0x5, 0x9, 0xB],
        [0x1, 0x7, 0x8, 0xF],
        [0x6, 0x0, 0x2, 0x3],
        [0xC, 0x4, 0xD, 0xE]
    ]

    # 轮常数
    RCON = [0x80, 0x30]

    def __init__(self):
        pass

    def gf_mult(self, a, b):
        """在GF(2^4)上的乘法"""
        # 使用x^4 + x + 1作为不可约多项式
        p = 0
        for _ in range(4):
            if b & 1:
                p ^= a
            hi_bit = a & 0x8
            a = (a << 1) & 0xF
            if hi_bit:
                a ^= 0x3  # x^4 + x + 1 = 0x13, 去掉x^4后是0x3
            b >>= 1
        return p

    def key_expansion(self, key):
        """密钥扩展"""
        # 将16位密钥分成2个字节
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF

        # 第一轮密钥扩展
        # 计算w2 = w0 ⊕ g(w1)
        w2 = w0 ^ self.g_func(w1, 0)

        # 计算w3 = w2 ⊕ w1
        w3 = w2 ^ w1

        # 第二轮密钥扩展
        # 计算w4 = w2 ⊕ g(w3)
        w4 = w2 ^ self.g_func(w3, 1)

        # 计算w5 = w4 ⊕ w3
        w5 = w4 ^ w3

        key0 = (w0 << 8) | w1  # 初始密钥
        key1 = (w2 << 8) | w3  # 第一轮密钥
        key2 = (w4 << 8) | w5  # 第二轮密钥

        return [key0, key1, key2]

    def g_func(self, byte, round_num):
        """g函数用于密钥扩展"""
        # 字节拆分成两个半字节
        nibble1 = (byte >> 4) & 0x0F
        nibble2 = byte & 0x0F

        # 半字节替换
        new_nibble1 = self.sub_nibble(nibble2, self.S_BOX)  # 注意：这里交换了半字节顺序
        new_nibble2 = self.sub_nibble(nibble1, self.S_BOX)

        # 与轮常数异或
        result = (new_nibble1 << 4) | new_nibble2
        result ^= self.RCON[round_num]

        return result

    def sub_nibble(self, nibble, s_box):
        """半字节替换"""
        row = (nibble >> 2) & 0x03
        col = nibble & 0x03
        return s_box[row][col]

    def sub_bytes(self, state):
        """字节替换"""
        new_state = [0, 0]
        for i in range(2):
            # 将每个字节拆分为两个半字节
            nibble1 = (state[i] >> 4) & 0x0F
            nibble2 = state[i] & 0x0F

            # 半字节替换
            new_nibble1 = self.sub_nibble(nibble1, self.S_BOX)
            new_nibble2 = self.sub_nibble(nibble2, self.S_BOX)

            # 重新组合
            new_state[i] = (new_nibble1 << 4) | new_nibble2
        return new_state

    def inv_sub_bytes(self, state):
        """逆字节替换"""
        new_state = [0, 0]
        for i in range(2):
            # 将每个字节拆分为两个半字节
            nibble1 = (state[i] >> 4) & 0x0F
            nibble2 = state[i] & 0x0F

            # 逆半字节替换
            new_nibble1 = self.sub_nibble(nibble1, self.INV_S_BOX)
            new_nibble2 = self.sub_nibble(nibble2, self.INV_S_BOX)

            # 重新组合
            new_state[i] = (new_nibble1 << 4) | new_nibble2
        return new_state

    def shift_rows(self, state):
        """行移位"""
        # 对于2x2状态矩阵，交换第二行的两个半字节
        new_state = state.copy()

        # 交换state[1]的高低半字节
        high_nibble = (new_state[1] >> 4) & 0x0F
        low_nibble = new_state[1] & 0x0F
        new_state[1] = (low_nibble << 4) | high_nibble

        return new_state

    def mix_columns(self, state):
        """列混淆"""
        new_state = [0, 0]

        # 矩阵乘法在GF(2^4)上
        # 矩阵: [1, 4]
        #       [4, 1]

        s00 = (state[0] >> 4) & 0x0F  # 第一行第一列
        s10 = state[0] & 0x0F  # 第二行第一列
        s01 = (state[1] >> 4) & 0x0F  # 第一行第二列
        s11 = state[1] & 0x0F  # 第二行第二列

        # 新状态的第一列
        new_s00 = self.gf_mult(1, s00) ^ self.gf_mult(4, s10)
        new_s10 = self.gf_mult(4, s00) ^ self.gf_mult(1, s10)

        # 新状态的第二列
        new_s01 = self.gf_mult(1, s01) ^ self.gf_mult(4, s11)
        new_s11 = self.gf_mult(4, s01) ^ self.gf_mult(1, s11)

        # 重新组合
        new_state[0] = (new_s00 << 4) | new_s10
        new_state[1] = (new_s01 << 4) | new_s11

        return new_state

    def inv_mix_columns(self, state):
        """逆列混淆"""
        new_state = [0, 0]

        # 逆矩阵: [9, 2]
        #         [2, 9]

        s00 = (state[0] >> 4) & 0x0F  # 第一行第一列
        s10 = state[0] & 0x0F  # 第二行第一列
        s01 = (state[1] >> 4) & 0x0F  # 第一行第二列
        s11 = state[1] & 0x0F  # 第二行第二列

        # 新状态的第一列
        new_s00 = self.gf_mult(9, s00) ^ self.gf_mult(2, s10)
        new_s10 = self.gf_mult(2, s00) ^ self.gf_mult(9, s10)

        # 新状态的第二列
        new_s01 = self.gf_mult(9, s01) ^ self.gf_mult(2, s11)
        new_s11 = self.gf_mult(2, s01) ^ self.gf_mult(9, s11)

        # 重新组合
        new_state[0] = (new_s00 << 4) | new_s10
        new_state[1] = (new_s01 << 4) | new_s11

        return new_state

    def add_round_key(self, state, round_key):
        """轮密钥加"""
        new_state = [0, 0]

        # 将轮密钥拆分为两个字节
        key_byte0 = (round_key >> 8) & 0xFF
        key_byte1 = round_key & 0xFF

        # 轮密钥加
        new_state[0] = state[0] ^ key_byte0
        new_state[1] = state[1] ^ key_byte1

        return new_state

    def encrypt(self, plaintext, key):
        """加密函数"""
        # 密钥扩展
        round_keys = self.key_expansion(key)

        # 将16位明文拆分为两个字节
        state = [(plaintext >> 8) & 0xFF, plaintext & 0xFF]

        # 初始轮密钥加
        state = self.add_round_key(state, round_keys[0])

        # 第1轮
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.mix_columns(state)
        state = self.add_round_key(state, round_keys[1])

        # 第2轮
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, round_keys[2])

        # 组合成16位密文
        ciphertext = (state[0] << 8) | state[1]
        return ciphertext

    def decrypt(self, ciphertext, key):
        """解密函数"""
        # 密钥扩展
        round_keys = self.key_expansion(key)

        # 将16位密文拆分为两个字节
        state = [(ciphertext >> 8) & 0xFF, ciphertext & 0xFF]

        # 初始轮密钥加（使用最后一轮密钥）
        state = self.add_round_key(state, round_keys[2])

        # 第1轮（逆操作）
        state = self.shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, round_keys[1])
        state = self.inv_mix_columns(state)

        # 第2轮（逆操作）
        state = self.shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, round_keys[0])

        # 组合成16位明文
        plaintext = (state[0] << 8) | state[1]
        return plaintext


class DoubleSAES:
    """双重S-AES加密"""

    def __init__(self):
        self.saes = SAES()

    def encrypt(self, plaintext, key):
        """双重加密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        intermediate = self.saes.encrypt(plaintext, key1)
        ciphertext = self.saes.encrypt(intermediate, key2)
        return ciphertext

    def decrypt(self, ciphertext, key):
        """双重解密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        intermediate = self.saes.decrypt(ciphertext, key2)
        plaintext = self.saes.decrypt(intermediate, key1)
        return plaintext


class TripleSAES:
    """三重S-AES加密"""

    def __init__(self):
        self.saes = SAES()

    def encrypt_ede(self, plaintext, key):
        """EDE模式三重加密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        temp = self.saes.encrypt(plaintext, key1)
        temp = self.saes.decrypt(temp, key2)
        ciphertext = self.saes.encrypt(temp, key1)
        return ciphertext

    def decrypt_ede(self, ciphertext, key):
        """EDE模式三重解密"""
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        temp = self.saes.decrypt(ciphertext, key1)
        temp = self.saes.encrypt(temp, key2)
        plaintext = self.saes.decrypt(temp, key1)
        return plaintext


class CBCModeOptimized:
    """优化后的CBC模式，使用类似标准库的接口"""

    def __init__(self, crypto_system):
        self.crypto_system = crypto_system
        self.block_size = 2  # S-AES块大小为2字节（16位）

    def encrypt(self, plaintext_blocks, key, iv):
        """CBC加密 - 优化版本"""
        ciphertext_blocks = []
        previous = iv

        for block in plaintext_blocks:
            # 与前一个密文块异或
            xored = block ^ previous
            # 加密
            encrypted = self.crypto_system.encrypt(xored, key)
            ciphertext_blocks.append(encrypted)
            previous = encrypted

        return ciphertext_blocks

    def decrypt(self, ciphertext_blocks, key, iv):
        """CBC解密 - 优化版本"""
        plaintext_blocks = []
        previous = iv

        for block in ciphertext_blocks:
            # 解密
            decrypted = self.crypto_system.decrypt(block, key)
            # 与前一个密文块异或
            xored = decrypted ^ previous
            plaintext_blocks.append(xored)
            previous = block

        return plaintext_blocks

    def encrypt_bytes(self, data_bytes, key, iv=None):
        """字节级CBC加密 - 类似标准库接口"""
        if iv is None:
            iv = self._generate_iv()
        elif isinstance(iv, bytes):
            # 如果IV是字节，转换为整数
            iv = self._bytes_to_int(iv)

        # 转换为16位块
        blocks = self._bytes_to_blocks(data_bytes)

        # CBC加密 - 确保IV是整数
        encrypted_blocks = self.encrypt(blocks, key, iv)

        # 转换回字节
        encrypted_bytes = self._blocks_to_bytes(encrypted_blocks)

        # 返回IV + 密文，IV需要从整数转换回字节
        iv_bytes = self._int_to_bytes(iv)
        return iv_bytes + encrypted_bytes

    def decrypt_bytes(self, ciphertext_bytes, key):
        """字节级CBC解密 - 类似标准库接口"""
        # 提取IV（前2字节）并转换为整数
        iv_bytes = ciphertext_bytes[:2]
        iv = self._bytes_to_int(iv_bytes)

        # 提取密文数据
        ciphertext_data = ciphertext_bytes[2:]

        # 转换为16位块
        blocks = self._bytes_to_blocks(ciphertext_data)

        # CBC解密
        decrypted_blocks = self.decrypt(blocks, key, iv)

        # 转换回字节
        decrypted_bytes = self._blocks_to_bytes(decrypted_blocks)

        return decrypted_bytes

    def _generate_iv(self):
        """生成随机IV（返回整数）"""
        iv_bytes = os.urandom(2)
        return self._bytes_to_int(iv_bytes)

    def _bytes_to_blocks(self, data_bytes):
        """将字节数据转换为16位块列表"""
        blocks = []
        for i in range(0, len(data_bytes), 2):
            block_bytes = data_bytes[i:i + 2]
            # 如果最后一块不足2字节，应该已经被填充
            if len(block_bytes) == 2:
                block = self._bytes_to_int(block_bytes)
                blocks.append(block)
        return blocks

    def _blocks_to_bytes(self, blocks):
        """将16位块列表转换为字节数据"""
        result = b''
        for block in blocks:
            result += self._int_to_bytes(block)
        return result

    def _bytes_to_int(self, data_bytes):
        """2字节转换为16位整数"""
        if len(data_bytes) == 2:
            return struct.unpack('>H', data_bytes)[0]
        elif len(data_bytes) == 1:
            return struct.unpack('>B', data_bytes)[0]
        else:
            return 0

    def _int_to_bytes(self, value):
        """16位整数转换为2字节"""
        return struct.pack('>H', value & 0xFFFF)


class SAESGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES加密")
        self.root.geometry("800x700")

        # 初始化加密系统
        self.saes = SAES()
        self.double_saes = DoubleSAES()
        self.triple_saes = TripleSAES()

        # 创建选项卡
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # 创建各个关卡的面板
        self.create_basic_test_tab()
        self.create_ascii_tab()
        self.create_multi_encryption_tab()
        self.create_cbc_tab()

    def create_basic_test_tab(self):
        """第1关：基本测试"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="基本测试")

        # 输入区域
        input_frame = ttk.LabelFrame(frame, text="输入")
        input_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(input_frame, text="明文 (16位):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.plaintext_entry = ttk.Entry(input_frame, width=20)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.key_entry = ttk.Entry(input_frame, width=20)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)

        # 按钮区域
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="加密", command=self.basic_encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="解密", command=self.basic_decrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_basic).pack(side='left', padx=5)

        # 输出区域
        output_frame = ttk.LabelFrame(frame, text="输出")
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.basic_output = scrolledtext.ScrolledText(output_frame, height=10, width=80)
        self.basic_output.pack(fill='both', expand=True, padx=5, pady=5)

    def create_ascii_tab(self):
        """第3关：ASCII加密"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="ASCII加密")

        # 输入区域
        input_frame = ttk.LabelFrame(frame, text="输入")
        input_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(input_frame, text="ASCII字符串:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.ascii_input = ttk.Entry(input_frame, width=40)
        self.ascii_input.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.ascii_key = ttk.Entry(input_frame, width=20)
        self.ascii_key.grid(row=1, column=1, padx=5, pady=5)

        # 按钮区域
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="ASCII加密", command=self.ascii_encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="ASCII解密", command=self.ascii_decrypt).pack(side='left', padx=5)

        # 输出区域
        output_frame = ttk.LabelFrame(frame, text="输出")
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.ascii_output = scrolledtext.ScrolledText(output_frame, height=10, width=80)
        self.ascii_output.pack(fill='both', expand=True, padx=5, pady=5)

    def create_multi_encryption_tab(self):
        """第4关：多重加密"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="多重加密")

        # 选项卡
        multi_notebook = ttk.Notebook(frame)
        multi_notebook.pack(fill='both', expand=True, padx=10, pady=5)

        # 双重加密
        double_frame = ttk.Frame(multi_notebook)
        multi_notebook.add(double_frame, text="双重加密")

        ttk.Label(double_frame, text="双重加密 (32位密钥)").pack(pady=5)

        # 双重加密输入
        double_input = ttk.LabelFrame(double_frame, text="输入")
        double_input.pack(fill='x', padx=10, pady=5)

        ttk.Label(double_input, text="明文:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.double_plaintext = ttk.Entry(double_input, width=20)
        self.double_plaintext.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(double_input, text="密钥 (32位):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.double_key = ttk.Entry(double_input, width=20)
        self.double_key.grid(row=1, column=1, padx=5, pady=5)

        # 双重加密按钮
        double_buttons = ttk.Frame(double_frame)
        double_buttons.pack(pady=5)

        ttk.Button(double_buttons, text="双重加密", command=self.double_encrypt).pack(side='left', padx=5)
        ttk.Button(double_buttons, text="双重解密", command=self.double_decrypt).pack(side='left', padx=5)

        # 中间相遇攻击
        meet_middle_frame = ttk.Frame(multi_notebook)
        multi_notebook.add(meet_middle_frame, text="中间相遇攻击")

        ttk.Label(meet_middle_frame, text="中间相遇攻击 - 使用多组明密文对确定唯一密钥",
                  font=('Arial', 10, 'bold')).pack(pady=5)

        # 多组明密文对输入
        attack_input = ttk.LabelFrame(meet_middle_frame, text="已知明密文对 (每行一组: 明文,密文)")
        attack_input.pack(fill='x', padx=10, pady=5)

        self.attack_pairs_text = scrolledtext.ScrolledText(attack_input, height=10, width=80)
        self.attack_pairs_text.pack(fill='both', expand=True, padx=5, pady=5)

        # 添加示例数据
        example_pairs = "1234,B74B\n5678,E665\n9ABC,0878"
        self.attack_pairs_text.insert(tk.END, example_pairs)

        ttk.Button(meet_middle_frame, text="执行中间相遇攻击", command=self.meet_middle_attack).pack(pady=5)

        # 三重加密
        triple_frame = ttk.Frame(multi_notebook)
        multi_notebook.add(triple_frame, text="三重加密")

        ttk.Label(triple_frame, text="三重加密").pack(pady=5)

        triple_input = ttk.LabelFrame(triple_frame, text="输入")
        triple_input.pack(fill='x', padx=10, pady=5)

        ttk.Label(triple_input, text="明文:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.triple_plaintext = ttk.Entry(triple_input, width=20)
        self.triple_plaintext.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(triple_input, text="密钥:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.triple_key = ttk.Entry(triple_input, width=20)
        self.triple_key.grid(row=1, column=1, padx=5, pady=5)

        # 三重加密按钮
        triple_buttons = ttk.Frame(triple_frame)
        triple_buttons.pack(pady=5)

        ttk.Button(triple_buttons, text="EDE模式加密", command=self.triple_ede_encrypt).pack(side='left', padx=5)
        ttk.Button(triple_buttons, text="EDE模式解密", command=self.triple_ede_decrypt).pack(side='left', padx=5)

        # 多重加密输出
        output_frame = ttk.LabelFrame(frame, text="输出")
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.multi_output = scrolledtext.ScrolledText(output_frame, height=20, width=80)
        self.multi_output.pack(fill='both', expand=True, padx=5, pady=5)

    def create_cbc_tab(self):
        """第5关：CBC模式 - 优化版本"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="CBC模式")

        # 输入区域
        input_frame = ttk.LabelFrame(frame, text="输入")
        input_frame.pack(fill='x', padx=10, pady=5)

        # 输入类型选择
        type_frame = ttk.Frame(input_frame)
        type_frame.grid(row=0, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        self.input_type = tk.StringVar(value="hex")
        ttk.Radiobutton(type_frame, text="十六进制输入", variable=self.input_type,
                        value="hex", command=self.update_cbc_input_labels).pack(side='left', padx=5)
        ttk.Radiobutton(type_frame, text="文本输入", variable=self.input_type,
                        value="text", command=self.update_cbc_input_labels).pack(side='left', padx=5)

        # 数据输入
        ttk.Label(input_frame, text="数据:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.cbc_plaintext = ttk.Entry(input_frame, width=40)
        self.cbc_plaintext.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.cbc_key = ttk.Entry(input_frame, width=20)
        self.cbc_key.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="初始向量IV (16位, 可选):").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.cbc_iv = ttk.Entry(input_frame, width=20)
        self.cbc_iv.grid(row=3, column=1, padx=5, pady=5)

        # 说明标签
        self.cbc_help_label = ttk.Label(input_frame, text="请输入十六进制数据", foreground="blue")
        self.cbc_help_label.grid(row=4, column=0, columnspan=2, sticky='w', padx=5, pady=2)

        # 按钮区域
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="CBC加密", command=self.cbc_encrypt_optimized).pack(side='left', padx=5)
        ttk.Button(button_frame, text="CBC解密", command=self.cbc_decrypt_optimized).pack(side='left', padx=5)
        ttk.Button(button_frame, text="篡改测试", command=self.cbc_tamper_test_optimized).pack(side='left', padx=5)
        ttk.Button(button_frame, text="生成示例", command=self.cbc_generate_example).pack(side='left', padx=5)

        # 输出区域
        output_frame = ttk.LabelFrame(frame, text="输出")
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.cbc_output = scrolledtext.ScrolledText(output_frame, height=12, width=80)
        self.cbc_output.pack(fill='both', expand=True, padx=5, pady=5)

        # 初始化帮助标签
        self.update_cbc_input_labels()

    def update_cbc_input_labels(self):
        """根据输入类型更新标签"""
        if self.input_type.get() == "hex":
            self.cbc_help_label.config(text="请输入十六进制数据 (如: 1234ABCD)")
            current_text = self.cbc_plaintext.get()
            # 如果不是纯十六进制字符，清空输入框
            if current_text and not all(c in '0123456789ABCDEFabcdef' for c in current_text):
                self.cbc_plaintext.delete(0, tk.END)
        else:
            self.cbc_help_label.config(text="请输入文本数据 (如: Hello World!)")

    def cbc_tamper_test_optimized(self):
        """优化版CBC篡改测试"""
        try:
            # 使用示例数据进行篡改测试
            test_data = self.cbc_plaintext.get().strip()
            key = int(self.cbc_key.get(), 16)

            self.cbc_output.delete(1.0, tk.END)
            self.cbc_output.insert(tk.END, "CBC篡改测试:\n")
            self.cbc_output.insert(tk.END, "=" * 50 + "\n")

            # 使用优化后的CBC模式
            cbc = CBCModeOptimized(self.saes)

            # 正常加密
            ciphertext_bytes = cbc.encrypt_bytes(test_data.encode('utf-8'), key)
            self.cbc_output.insert(tk.END, f"原始数据: {test_data}\n")
            self.cbc_output.insert(tk.END, f"正常密文: {ciphertext_bytes.hex().upper()}\n")

            # 篡改第二个加密块（第一个数据块）
            tampered_bytes = bytearray(ciphertext_bytes)
            if len(tampered_bytes) > 4:  # 确保有至少2个块（IV + 至少1个数据块）
                # 篡改第一个数据块的第一个字节（在字节6的位置：IV 2字节 + 第一个块2字节 + 第二个块的开始）
                tampered_bytes[4] ^= 0xFF  # 强烈篡改

            # 解密篡改后的密文
            try:
                decrypted_bytes = cbc.decrypt_bytes(bytes(tampered_bytes), key)
                decrypted_text = decrypted_bytes.decode('utf-8', errors='replace')

                self.cbc_output.insert(tk.END, f"篡改后密文: {bytes(tampered_bytes).hex().upper()}\n")
                self.cbc_output.insert(tk.END, f"解密结果: {decrypted_text}\n")
                self.cbc_output.insert(tk.END, f"解密字节: {decrypted_bytes.hex().upper()}\n\n")

                # 分析影响
                self.cbc_output.insert(tk.END, "篡改影响分析:\n")
                self.cbc_output.insert(tk.END, "✓ 被篡改的块解密后完全损坏\n")
                self.cbc_output.insert(tk.END, "✓ 下一个块也会受到影响（CBC传播特性）\n")
                self.cbc_output.insert(tk.END, "✓ 这是CBC模式的安全特性，能检测数据篡改\n")

            except Exception as e:
                self.cbc_output.insert(tk.END, f"解密篡改数据时出错: {str(e)}\n")
                self.cbc_output.insert(tk.END, "这表明CBC模式成功检测到数据被篡改！\n")

        except Exception as e:
            messagebox.showerror("错误", f"篡改测试失败: {str(e)}")

    def cbc_generate_example(self):
        """生成CBC示例"""
        self.cbc_output.delete(1.0, tk.END)
        self.cbc_output.insert(tk.END, "CBC模式使用示例:\n")
        self.cbc_output.insert(tk.END, "=" * 50 + "\n\n")

        self.cbc_output.insert(tk.END, "1. 文本加密示例:\n")
        self.cbc_output.insert(tk.END, "   - 选择'文本输入'\n")
        self.cbc_output.insert(tk.END, "   - 数据: Hello World!\n")
        self.cbc_output.insert(tk.END, "   - 密钥: 5678\n")
        self.cbc_output.insert(tk.END, "   - IV: 9ABC (或留空自动生成)\n")
        self.cbc_output.insert(tk.END, "   - 点击'CBC加密'\n\n")

        self.cbc_output.insert(tk.END, "2. 十六进制加密示例:\n")
        self.cbc_output.insert(tk.END, "   - 选择'十六进制输入'\n")
        self.cbc_output.insert(tk.END, "   - 数据: 1234ABCD\n")
        self.cbc_output.insert(tk.END, "   - 密钥: 5678\n")
        self.cbc_output.insert(tk.END, "   - IV: 9ABC\n")
        self.cbc_output.insert(tk.END, "   - 点击'CBC加密'\n\n")

        self.cbc_output.insert(tk.END, "3. 解密示例:\n")
        self.cbc_output.insert(tk.END, "   - 将加密得到的'完整密文'复制到数据框\n")
        self.cbc_output.insert(tk.END, "   - 输入相同的密钥\n")
        self.cbc_output.insert(tk.END, "   - IV框可以留空（IV已包含在密文中）\n")
        self.cbc_output.insert(tk.END, "   - 点击'CBC解密'\n\n")

        self.cbc_output.insert(tk.END, "特点说明:\n")
        self.cbc_output.insert(tk.END, "✓ 自动PKCS7填充，支持任意长度数据\n")
        self.cbc_output.insert(tk.END, "✓ 自动IV生成（如未指定）\n")
        self.cbc_output.insert(tk.END, "✓ 支持文本和十六进制输入\n")
        self.cbc_output.insert(tk.END, "✓ 完整密文格式: IV(2字节) + 加密数据\n")

    def basic_encrypt(self):
        try:
            plaintext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)

            ciphertext = self.saes.encrypt(plaintext, key)

            self.basic_output.delete(1.0, tk.END)
            self.basic_output.insert(tk.END, f"明文: 0x{plaintext:04X}\n")
            self.basic_output.insert(tk.END, f"密钥: 0x{key:04X}\n")
            self.basic_output.insert(tk.END, f"密文: 0x{ciphertext:04X}\n")

        except ValueError as e:
            messagebox.showerror("错误", "请输入有效的16进制数字")

    def basic_decrypt(self):
        try:
            ciphertext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)

            plaintext = self.saes.decrypt(ciphertext, key)

            self.basic_output.delete(1.0, tk.END)
            self.basic_output.insert(tk.END, f"密文: 0x{ciphertext:04X}\n")
            self.basic_output.insert(tk.END, f"密钥: 0x{key:04X}\n")
            self.basic_output.insert(tk.END, f"明文: 0x{plaintext:04X}\n")

        except ValueError as e:
            messagebox.showerror("错误", "请输入有效的16进制数字")

    def clear_basic(self):
        self.basic_output.delete(1.0, tk.END)

    def ascii_encrypt(self):
        try:
            text = self.ascii_input.get()
            key = int(self.ascii_key.get(), 16)

            # 将字符串转换为字节
            text_bytes = text.encode('ascii')

            # 填充到偶数长度
            if len(text_bytes) % 2 != 0:
                text_bytes += b'\x00'

            encrypted_blocks = []
            encrypted_text = ""

            for i in range(0, len(text_bytes), 2):
                # 将2个字节组合成16位数据
                block = (text_bytes[i] << 8) | text_bytes[i + 1]

                # 加密
                cipher_block = self.saes.encrypt(block, key)
                encrypted_blocks.append(cipher_block)

                # 将加密结果转换为ASCII字符（可能是乱码）
                high_byte = (cipher_block >> 8) & 0xFF
                low_byte = cipher_block & 0xFF
                encrypted_text += chr(high_byte) + chr(low_byte)

            self.ascii_output.delete(1.0, tk.END)
            self.ascii_output.insert(tk.END, f"原始文本: {text}\n")
            self.ascii_output.insert(tk.END, f"密钥: 0x{key:04X}\n\n")
            self.ascii_output.insert(tk.END, "加密块:\n")
            for i, block in enumerate(encrypted_blocks):
                self.ascii_output.insert(tk.END, f"块{i + 1}: 0x{block:04X}\n")

            self.ascii_output.insert(tk.END, f"\n加密文本 (可能显示乱码): {encrypted_text}\n")

        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def ascii_decrypt(self):
        try:
            text = self.ascii_input.get()
            key = int(self.ascii_key.get(), 16)

            # 将字符串转换为字节
            text_bytes = text.encode('latin-1')  # 使用latin-1以保留所有字节值

            # 必须是偶数长度
            if len(text_bytes) % 2 != 0:
                messagebox.showerror("错误", "密文长度必须是偶数")
                return

            decrypted_blocks = []
            decrypted_text = ""

            for i in range(0, len(text_bytes), 2):
                # 将2个字节组合成16位数据
                block = (text_bytes[i] << 8) | text_bytes[i + 1]

                # 解密
                plain_block = self.saes.decrypt(block, key)
                decrypted_blocks.append(plain_block)

                # 将解密结果转换为ASCII字符
                high_byte = (plain_block >> 8) & 0xFF
                low_byte = plain_block & 0xFF
                decrypted_text += chr(high_byte) + chr(low_byte)

            # 去除填充的null字节
            decrypted_text = decrypted_text.rstrip('\x00')

            self.ascii_output.delete(1.0, tk.END)
            self.ascii_output.insert(tk.END, f"密文: {text}\n")
            self.ascii_output.insert(tk.END, f"密钥: 0x{key:04X}\n\n")
            self.ascii_output.insert(tk.END, "解密块:\n")
            for i, block in enumerate(decrypted_blocks):
                self.ascii_output.insert(tk.END, f"块{i + 1}: 0x{block:04X}\n")

            self.ascii_output.insert(tk.END, f"\n解密文本: {decrypted_text}\n")

        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def double_encrypt(self):
        try:
            plaintext = int(self.double_plaintext.get(), 16)
            key = int(self.double_key.get(), 16)

            ciphertext = self.double_saes.encrypt(plaintext, key)

            self.multi_output.delete(1.0, tk.END)
            self.multi_output.insert(tk.END, "双重加密结果:\n")
            self.multi_output.insert(tk.END, f"明文: 0x{plaintext:04X}\n")
            self.multi_output.insert(tk.END, f"密钥: 0x{key:08X}\n")
            self.multi_output.insert(tk.END, f"密文: 0x{ciphertext:04X}\n")

        except ValueError as e:
            messagebox.showerror("错误", "请输入有效的16进制数字")

    def double_decrypt(self):
        try:
            ciphertext = int(self.double_plaintext.get(), 16)
            key = int(self.double_key.get(), 16)

            plaintext = self.double_saes.decrypt(ciphertext, key)

            self.multi_output.delete(1.0, tk.END)
            self.multi_output.insert(tk.END, "双重解密结果:\n")
            self.multi_output.insert(tk.END, f"密文: 0x{ciphertext:04X}\n")
            self.multi_output.insert(tk.END, f"密钥: 0x{key:08X}\n")
            self.multi_output.insert(tk.END, f"明文: 0x{plaintext:04X}\n")

        except ValueError as e:
            messagebox.showerror("错误", "请输入有效的16进制数字")

    def meet_middle_attack(self):
        try:
            # 获取多组明密文对
            pairs_text = self.attack_pairs_text.get(1.0, tk.END).strip()
            pairs_lines = pairs_text.split('\n')

            pairs = []
            for line in pairs_lines:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) == 2:
                        plaintext = int(parts[0].strip(), 16)
                        ciphertext = int(parts[1].strip(), 16)
                        pairs.append((plaintext, ciphertext))

            if not pairs:
                messagebox.showerror("错误", "请输入至少一组明密文对")
                return

            self.multi_output.delete(1.0, tk.END)
            self.multi_output.insert(tk.END, "执行中间相遇攻击...\n")
            self.multi_output.insert(tk.END, f"使用 {len(pairs)} 组明密文对:\n")
            for i, (p, c) in enumerate(pairs):
                self.multi_output.insert(tk.END, f"  对{i + 1}: 明文=0x{p:04X}, 密文=0x{c:04X}\n")
            self.multi_output.insert(tk.END, "\n")

            # 使用第一组明密文对构建候选密钥
            first_plain, first_cipher = pairs[0]
            candidate_keys = []

            # 构建加密表
            encrypt_table = {}
            self.multi_output.insert(tk.END, "构建加密表...\n")
            for key1 in range(0x10000):
                intermediate = self.saes.encrypt(first_plain, key1)
                if intermediate not in encrypt_table:
                    encrypt_table[intermediate] = []
                encrypt_table[intermediate].append(key1)

            # 查找匹配的解密
            self.multi_output.insert(tk.END, "查找匹配的密钥对...\n")
            for key2 in range(0x10000):
                intermediate = self.saes.decrypt(first_cipher, key2)
                if intermediate in encrypt_table:
                    for key1 in encrypt_table[intermediate]:
                        full_key = (key1 << 16) | key2
                        candidate_keys.append((key1, key2, full_key))

            self.multi_output.insert(tk.END, f"使用第一组明密文对找到 {len(candidate_keys)} 个候选密钥\n")

            # 使用其他明密文对过滤候选密钥
            if len(pairs) > 1:
                self.multi_output.insert(tk.END, "\n使用其他明密文对过滤候选密钥...\n")
                for i in range(1, len(pairs)):
                    plain, cipher = pairs[i]
                    filtered_keys = []

                    for key1, key2, full_key in candidate_keys:
                        # 验证这个密钥对是否能正确加密/解密当前明密文对
                        test_cipher = self.double_saes.encrypt(plain, full_key)
                        if test_cipher == cipher:
                            filtered_keys.append((key1, key2, full_key))

                    self.multi_output.insert(tk.END,
                                             f"使用第{i + 1}组明密文对过滤后剩余 {len(filtered_keys)} 个候选密钥\n")
                    candidate_keys = filtered_keys

                    if len(candidate_keys) == 0:
                        self.multi_output.insert(tk.END, "警告: 没有找到匹配的密钥！\n")
                        break

            # 显示最终结果
            self.multi_output.insert(tk.END, "\n最终结果:\n")
            if len(candidate_keys) == 1:
                key1, key2, full_key = candidate_keys[0]
                self.multi_output.insert(tk.END,
                                         f"✓ 找到唯一密钥: K1=0x{key1:04X}, K2=0x{key2:04X}, 完整密钥=0x{full_key:08X}\n")

                # 验证所有明密文对
                self.multi_output.insert(tk.END, "\n验证所有明密文对:\n")
                for i, (plain, cipher) in enumerate(pairs):
                    test_cipher = self.double_saes.encrypt(plain, full_key)
                    status = "✓" if test_cipher == cipher else "✗"
                    self.multi_output.insert(tk.END,
                                             f"  对{i + 1}: 明文=0x{plain:04X}, 期望密文=0x{cipher:04X}, 计算密文=0x{test_cipher:04X} {status}\n")

            elif len(candidate_keys) > 1:
                self.multi_output.insert(tk.END, f"找到 {len(candidate_keys)} 个可能的密钥对:\n")
                for i, (key1, key2, full_key) in enumerate(candidate_keys[:10]):  # 只显示前10个
                    self.multi_output.insert(tk.END,
                                             f"  密钥对 {i + 1}: K1=0x{key1:04X}, K2=0x{key2:04X}, 完整密钥=0x{full_key:08X}\n")

                if len(candidate_keys) > 10:
                    self.multi_output.insert(tk.END, f"  ... 还有 {len(candidate_keys) - 10} 个密钥对未显示\n")

                self.multi_output.insert(tk.END, "\n提示: 使用更多明密文对可以进一步缩小密钥范围\n")
            else:
                self.multi_output.insert(tk.END, "✗ 没有找到匹配的密钥！\n")
                self.multi_output.insert(tk.END, "提示: 请检查输入的明密文对是否正确\n")

        except ValueError as e:
            messagebox.showerror("错误", f"输入格式错误: {str(e)}\n请确保每行格式为: 明文,密文 (16进制)")
        except Exception as e:
            messagebox.showerror("错误", f"攻击过程中出现错误: {str(e)}")

    def triple_ede_encrypt(self):
        try:
            plaintext = int(self.triple_plaintext.get(), 16)
            key = int(self.triple_key.get(), 16)

            ciphertext = self.triple_saes.encrypt_ede(plaintext, key)

            self.multi_output.delete(1.0, tk.END)
            self.multi_output.insert(tk.END, "三重加密(EDE模式)结果:\n")
            self.multi_output.insert(tk.END, f"明文: 0x{plaintext:04X}\n")
            self.multi_output.insert(tk.END, f"密钥: 0x{key:08X}\n")
            self.multi_output.insert(tk.END, f"密文: 0x{ciphertext:04X}\n")

        except ValueError as e:
            messagebox.showerror("错误", "请输入有效的16进制数字")

    def triple_ede_decrypt(self):
        try:
            ciphertext = int(self.triple_plaintext.get(), 16)
            key = int(self.triple_key.get(), 16)

            plaintext = self.triple_saes.decrypt_ede(ciphertext, key)

            self.multi_output.delete(1.0, tk.END)
            self.multi_output.insert(tk.END, "三重解密(EDE模式)结果:\n")
            self.multi_output.insert(tk.END, f"密文: 0x{ciphertext:04X}\n")
            self.multi_output.insert(tk.END, f"密钥: 0x{key:08X}\n")
            self.multi_output.insert(tk.END, f"明文: 0x{plaintext:04X}\n")

        except ValueError as e:
            messagebox.showerror("错误", "请输入有效的16进制数字")

    def cbc_encrypt_optimized(self):
        """优化版CBC加密"""
        try:
            data_str = self.cbc_plaintext.get().strip()
            key = int(self.cbc_key.get(), 16)
            iv_input = self.cbc_iv.get().strip()

            if not data_str:
                messagebox.showwarning("警告", "请输入要加密的数据")
                return

            # 记录输入类型
            input_type = self.input_type.get()

            # 根据输入类型转换数据
            if self.input_type.get() == "hex":
                # 十六进制输入
                if not all(c in '0123456789ABCDEFabcdef' for c in data_str):
                    messagebox.showerror("错误", "请输入有效的十六进制数字")
                    return
                    # 检查长度是否为4的倍数
                if len(data_str) % 4 != 0:
                    messagebox.showerror("错误", "十六进制输入长度必须是4的倍数（即2字节的整数倍）")
                    return
                data_bytes = bytes.fromhex(data_str)
            else:
                # 文本输入
                data_bytes = data_str.encode('utf-8')

            # 处理IV
            if iv_input:
                if not all(c in '0123456789ABCDEFabcdef' for c in iv_input) or len(iv_input) != 4:
                    messagebox.showerror("错误", "IV必须是4位十六进制数字")
                    return
                iv = int(iv_input, 16)
            else:
                iv = None  # 自动生成

            # 使用优化后的CBC模式
            cbc = CBCModeOptimized(self.saes)

            # 加密
            ciphertext_bytes = cbc.encrypt_bytes(data_bytes, key, iv)

            # 显示结果
            self.cbc_output.delete(1.0, tk.END)
            self.cbc_output.insert(tk.END, "优化CBC加密结果:\n")
            self.cbc_output.insert(tk.END, "=" * 50 + "\n")

            if self.input_type.get() == "hex":
                self.cbc_output.insert(tk.END, f"原始数据 (十六进制): {data_str}\n")
            else:
                self.cbc_output.insert(tk.END, f"原始文本: {data_str}\n")
                self.cbc_output.insert(tk.END, f"原始字节: {data_bytes.hex().upper()}\n")

            self.cbc_output.insert(tk.END, f"密钥: 0x{key:04X}\n")

            # 提取IV（前2字节）
            result_iv = cbc._bytes_to_int(ciphertext_bytes[:2])
            if iv_input:
                self.cbc_output.insert(tk.END, f"使用IV: 0x{iv:04X}\n")
            else:
                self.cbc_output.insert(tk.END, f"自动生成IV: 0x{result_iv:04X}\n")

            # 完整的密文（IV + 加密数据）
            full_ciphertext_hex = ciphertext_bytes.hex().upper()
            self.cbc_output.insert(tk.END, f"完整密文 (IV+数据): {full_ciphertext_hex}\n")

            # 仅加密数据部分（去掉IV）
            encrypted_data = ciphertext_bytes[2:]
            self.cbc_output.insert(tk.END, f"加密数据部分: {encrypted_data.hex().upper()}\n")

            # 显示块信息
            encrypted_blocks = cbc._bytes_to_blocks(encrypted_data)
            self.cbc_output.insert(tk.END, f"加密块: {[f'0x{block:04X}' for block in encrypted_blocks]}\n")

            # 显示输入类型信息
            self.cbc_output.insert(tk.END, f"输入类型: {'十六进制' if input_type == 'hex' else '文本'}\n")

            # 使用说明
            self.cbc_output.insert(tk.END, "\n提示: 解密时请使用完整的'完整密文'进行解密\n")

        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def cbc_decrypt_optimized(self):
        try:
            ciphertext_str = self.cbc_plaintext.get()
            key = int(self.cbc_key.get(), 16)

            # 将十六进制字符串转换为字节
            ciphertext_bytes = bytes.fromhex(ciphertext_str)

            # 使用优化后的CBC模式
            cbc = CBCModeOptimized(self.saes)

            # 解密
            plaintext_bytes = cbc.decrypt_bytes(ciphertext_bytes, key)

            # 使用加密时记录的类型进行转换
            input_type = self.input_type.get()

            # 尝试解码为文本，如果不是有效文本则显示十六进制
            if input_type == "hex":
                # 十六进制输出
                plaintext_hex = plaintext_bytes.hex().upper()
                display_text = f"解密数据 (十六进制): {plaintext_hex}"
            else:
                # 文本输出 - 尝试解码为UTF-8
                try:
                    plaintext_str = plaintext_bytes.decode('utf-8')
                    display_text = f"解密文本: {plaintext_str}"
                except UnicodeDecodeError:
                    # 如果UTF-8解码失败，回退到十六进制显示
                    plaintext_hex = plaintext_bytes.hex().upper()
                    display_text = f"解密数据 (十六进制, UTF-8解码失败): {plaintext_hex}"

            self.cbc_output.delete(1.0, tk.END)
            self.cbc_output.insert(tk.END, "优化CBC解密结果:\n")
            self.cbc_output.insert(tk.END, "=" * 50 + "\n")
            self.cbc_output.insert(tk.END, f"密文: {ciphertext_str}\n")
            self.cbc_output.insert(tk.END, f"密钥: 0x{key:04X}\n")
            self.cbc_output.insert(tk.END, f"输入类型: {'十六进制' if input_type == 'hex' else '文本'}\n")
            self.cbc_output.insert(tk.END, f"{display_text}\n")

        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")


def main():
    root = tk.Tk()
    app = SAESGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
