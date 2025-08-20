'''
Dynamic Decentralized Functional Encryption with Strong Security
https://eprint.iacr.org/2022/1532
Fig. 7: FH-DMCFE
基于charm-crypto的实现尝试
author: legendary_ticket_gate_7A7B
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
import numpy as np

class NPS22():
    def __init__(self, user_number, vector_length):
        self.groupG = PairingGroup('SS512')
        self.n = user_number
        self.N = vector_length
        self.dim = vector_length + 2
        self.all_para = {}
        self.g1 = self.groupG.random(G1)
        self.g2 = self.groupG.random(G2)
        self.H1 = lambda x: self.g1 ** self.groupG.hash(str(x), ZR)
        self.H2 = lambda x: self.g2 ** self.groupG.hash(str(x), ZR)

    def solve(self, augmented_matrix):
        """
        高斯消元法求解线性方程组
        输入: 增广矩阵 [A | b] (与原始代码完全兼容)
        输出: 解向量 x
        """
        n = len(augmented_matrix)
        # 创建数值矩阵副本
        matrix = [row[:] for row in augmented_matrix]

        # 前向消元
        for pivot in range(n):
            # 查找主元
            max_row = pivot
            for i in range(pivot + 1, n):
                if abs(int(matrix[i][pivot])) > abs(int(matrix[max_row][pivot])):
                    max_row = i

            # 交换行
            matrix[pivot], matrix[max_row] = matrix[max_row], matrix[pivot]

            # 归一化主元行
            pivot_val = matrix[pivot][pivot]
            if pivot_val == 0:
                raise ValueError("矩阵奇异，无法求解")

            for j in range(pivot, len(matrix[pivot])):
                matrix[pivot][j] = matrix[pivot][j] / pivot_val

            # 消去下方元素
            for i in range(pivot + 1, n):
                factor = matrix[i][pivot]
                for j in range(pivot, len(matrix[i])):
                    matrix[i][j] = matrix[i][j] - factor * matrix[pivot][j]

        # 回代求解
        x = [0] * n
        for i in range(n - 1, -1, -1):
            x[i] = matrix[i][-1]  # 右侧常数项
            for j in range(i + 1, n):
                x[i] = x[i] - matrix[i][j] * x[j]

        return x

    def generate_invertible_matrix(self):
        """生成可逆矩阵及其逆矩阵"""
        dim = self.dim
        # 生成随机矩阵
        M = [[self.groupG.random(ZR) for _ in range(dim)] for __ in range(dim)]

        # 创建单位矩阵
        I = [[self.groupG.init(ZR, 1) if i == j else self.groupG.init(ZR, 0)
              for j in range(dim)] for i in range(dim)]

        # 计算逆矩阵
        M_inv = []
        for col in range(dim):
            # 构建增广矩阵 [M | I_col]
            aug_matrix = []
            for i in range(dim):
                aug_row = M[i][:]  # 原始矩阵行
                aug_row.append(I[i][col])  # 添加单位矩阵列
                aug_matrix.append(aug_row)

            # 使用原始高斯消元求解
            inv_col = self.solve(aug_matrix)
            M_inv.append(inv_col)

        # 转置得到逆矩阵
        M_inv = [[M_inv[j][i] for j in range(dim)] for i in range(dim)]
        return M, M_inv

    def generate_bases(self):
        """生成所有基对"""
        self.B = []  # 基矩阵 B_i
        self.B_star = []  # 对偶基矩阵 B_i^*

        for _ in range(self.n):
            M, M_inv = self.generate_invertible_matrix()
            # B_i = M
            self.B.append(M)
            # B_i^* = (M^{-1})^T
            M_inv_trans = np.array(M_inv).T.tolist()
            self.B_star.append(M_inv_trans)

    def generate_random_scalars(self):
        """生成满足约束的随机标量"""
        # 生成随机s_i (∑s_i=0)
        s = [self.groupG.random(ZR) for _ in range(self.n - 1)]
        s.append(-sum(s))
        # 生成随机t_i (∑t_i=0)
        t = [self.groupG.random(ZR) for _ in range(self.n - 1)]
        t.append(-sum(t))

        return s, t

    def generate_keys(self):
        """生成所有ski和eki"""
        self.generate_bases()
        s, t = self.generate_random_scalars()
        sk_list = []
        ek_list = []
        vec = [[]]
        for i in range(self.n):
            # 构建ski = (s_i, b_{i,1}^*, ..., b_{i,N}^*, B_{i,N+1}^*, B_{i,N+2}^*, b_{i,N+3}^*)
            b_star = {}
            for j in range(self.dim):
                b_star_temp = []
                for k in range(self.N):
                    vec = self.B_star[i][k][j]
                    b_star_temp.append(vec)
                b_star[j] = b_star_temp
            # 提取特定行向量
            B_Np1_star = self.B_star[i][self.N]
            B_Np2_star = self.B_star[i][self.N + 1]
            b_Np3_star = self.groupG.random(ZR)

            sk_list.append({
                's_i': s[i],
                'b_star': b_star,  # N个向量
                'B_N+1_star': B_Np1_star,  # dim个向量
                'B_N+2_star': B_Np2_star,  # dim个向量
                'B_N+3_star': b_Np3_star  # 单个向量
            })
            # 构建eki = (t_i, b_{i,1}, ..., b_{i,N}, B_{i,N+1}, B_{i,N+2}, b_{i,N+4})
            b = {}
            for j in range(self.dim):
                b_temp = []
                for k in range(self.N):
                    vec = self.B[i][k][j]
                    b_temp.append(vec)
                b[j] = b_temp

            # 提取特定行向量
            B_Np1 = self.B[i][self.N]
            B_Np2 = self.B[i][self.N + 1]
            b_Np4 = self.groupG.random(ZR) # 注意索引：N+4行对应索引N+3

            ek_list.append({
                't_i': t[i],
                'b': b,  # N个向量
                'B_N+1': B_Np1,  # dim个向量
                'B_N+2': B_Np2,  # dim个向量
                'B_N+4': b_Np4  # 单个向量
            })

        return sk_list, ek_list


    def DKGen(self, sk_i, tagf, y_i):
        miu = self.H2(tagf)
        pi_i = self.groupG.random(ZR)
        d_i = [1] * self.dim #[self.groupG.init(G2, 1)] * (self.dim + 3)
        # 第一部分: Σ y_i[k] * b_{i,k}^*
        for i in range(self.dim):
            for k in range(self.N):
                d_i[i] *= self.g2 ** (sk_i['b_star'][i][k] * y_i[k])
            d_i[i] *= miu ** (sk_i['B_N+1_star'][i] * sk_i['s_i'])
            d_i[i] *= miu ** sk_i['B_N+2_star'][i]
        return d_i

    def Enc(self, ek_i, tag, x_i):
        omega = self.H1(tag)
        rho_i = self.groupG.random(ZR)
        c_i = [1] * self.dim #[self.groupG.init(G1, 1)] * (self.dim + 3)
        # 第一部分: Σ y_i[k] * b_{i,k}^*
        for i in range(self.dim):
            for k in range(self.N):
                c_i[i] *= self.g1 ** (ek_i['b'][i][k] * x_i[k])
            c_i[i] *= (omega ** ek_i['B_N+1'][i])
            c_i[i] *= (omega ** (ek_i['B_N+2'][i] * ek_i['t_i']))
        return c_i


    def Dec(self, d_list, c_list, log_range):
        out_T = 1
        for i in range(self.n):
            c_i = c_list[i]
            d_i = d_list[i]
            for j in range(self.dim):
                out_T *= pair(c_i[j], d_i[j])
        gt_guess = pair(self.g1, self.g2)
        for guess in range(log_range):
            if gt_guess ** guess == out_T:
                print("Dec success: ",guess)
                return guess
        return out_T
