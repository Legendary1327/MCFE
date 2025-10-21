'''
[1] Y. Chang, K. Zhang, J. Gong, and H. Qian,
“Privacy-Preserving Federated Learning via Functional Encryption, Revisited,”
IEEE Transactions on Information Forensics and Security, vol. 18, pp. 1855–1869, 2023, doi: 10.1109/TIFS.2023.3255171.
'''

import time
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, extract_key
import random

class CZGQ():
    def __init__(self):
        self.groupG = PairingGroup('SS512')
        self.all_para = {}
        self.g1 = self.groupG.random(G1)
        self.g2 = self.groupG.random(G2)
        self.fixedSeed = 5


    def Setup(self, user_number):
        self.H1 = lambda x: self.g1 ** self.groupG.hash(str(x), ZR)
        self.H2 = lambda x: self.g2 ** self.groupG.hash(str(x), ZR)
        T = self.generate_random_scalars(user_number)
        Ti = {}
        si = {}
        sk_temp = {}
        self.PRFSeed = {}
        for i in range(user_number):
            si[i] = self.groupG.random(ZR)
            Ti[i] = T[i]
            sk_temp[i] = {'si':si[i], 'Ti':Ti[i]}

            self.PRFSeed[i] = random.random()

        ek = si
        sk = sk_temp
        return ek, sk

    def generate_random_scalars(self, n):
        """生成满足约束的随机标量"""
        # 生成随机s_i (∑s_i=0)
        T = [self.groupG.random(ZR) for _ in range(n - 1)]
        T.append(-sum(T))
        return T


    def KeyGen(self, sk_i, y_i, all_y):
        vy = self.H2(all_y)
        di = (self.g2 ** (y_i * sk_i['si'])) * (vy ** sk_i['Ti'])
        return di

    def PRF(self, seed, label, user_id):
        seed_str = str(seed)
        label_str = str(label)
        user_id_str = str(user_id)

        # Concatenate all parts to create a unique input for each user in each round
        prf_input = seed_str + label_str + user_id_str

        # Hash the input into the finite field Z_p (represented by ZR)
        session_key = self.groupG.hash(prf_input, ZR)
        return session_key

    def Enc(self, ek_i, x_i, id, model=1, label="l"):
        if model == 1:
            ul = self.H1(label)
            ct_i = (ul ** ek_i) * (self.g1 ** x_i)
            sessionKey = 1
        else:
            ul = self.H1(label)
            sessionKey = self.PRF(self.PRFSeed[id],label, id)
            #print(sessionKey)
            ct_i = (ul ** ek_i) * (self.g1 ** (x_i + sessionKey))
            print(sessionKey)
        return ct_i, sessionKey


    def Dec(self,ct, dk, sessionKey, y, log_range, user_number, label):
        d = 1
        for i in range(user_number):
            d *= dk[i]
        pair_left = 1
        ul = self.H1(label)
        for i in range(user_number):
            pair_left *= pair(ct[i], self.g2 ** y[i])
        pair_right = pair(ul, d)
        result = pair_left / pair_right
        g_T = pair(self.g1, self.g2)
        all_sek = 0
        for i in range(user_number):
            all_sek += sessionKey[i]
        result /= (g_T ** all_sek)
        for alpha_guess in range(0,log_range):
            if g_T ** alpha_guess == result:
                print("FE success:", alpha_guess)
                return alpha_guess #- (user_number * self.fixedSeed)

        return result
