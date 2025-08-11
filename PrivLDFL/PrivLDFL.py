'''

[1] B. Yu, J. Zhao, K. Zhang, J. Gong, and H. Qian, “Lightweight and Dynamic Privacy-Preserving Federated Learning via Functional Encryption,” IEEE Transactions on Information Forensics and Security, pp. 1–1, 2025, doi: 10.1109/TIFS.2025.3540312.
'''

import time
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, extract_key
#from analysis.tools.sym_enc import *
from charm.toolbox.msp import MSP
#from copy import *
import numpy as np
from AoNE_Pair import AoNE

class PrivLDFL():
    def __init__(self, user_list):
        self.groupG = PairingGroup('SS512')
        self.util = MSP(self.groupG, False)
        self.user_list = user_list
        self.all_para = {}


    def Setup(self):
        self.H1 = lambda x: (self.groupG.hash(str(x), ZR),self.groupG.hash(str(x), ZR))
        # H2: hashes a value into G2^2 (a tuple of two G2 elements)
        self.H2 = lambda x: (self.groupG.hash(str(x), ZR),self.groupG.hash(str(x), ZR))
        #print(self.H1("123"))
        #print(self.H2("123"))
        self.aone = AoNE(self.user_list)
        APP = self.aone.Setup()
        PP = {'H1':self.H1, 'H2':self.H2, 'APP':APP, 'g1':self.groupG.random(G1),'g2':self.groupG.random(G2)}
        return APP,PP

    def KeyGen(self, APP, PP):

        pk = {}
        skpk = {}
        ekpk = {}
        for user in self.user_list:
            s = self.groupG.random(ZR, count=2) # Returns a list of two ZR elements
            ek_pk = s
            Apk, Ask = self.aone.KeyGen(APP)
            pk[user] = Apk
            skpk[user] = [s,Ask]
            ekpk[user] = s
        return pk, skpk, ekpk


    def Enc(self, x, y, PP, APP, pk, skpk, ekpk, label="l"):

        ct = {}
        dk = {}
        for user in self.user_list:
            ek = ekpk[user]
            ul = PP['H1'](label)
            uls = ul[0] * ek[0] + ul[1] * ek[1]
            x_group = self.groupG.init(ZR, x)
            cpk = (PP['g1'] ** uls) * (PP['g1'] ** x_group)
            ct[user] = cpk

            vy = PP['H2'](str(y))
            #print("vy:1",vy)
            T_pk = np.array([[self.groupG.random(ZR) for _ in range(2)] for _ in range(2)])
            T_pk_dot = T_pk.dot(vy)
            y_group = self.groupG.init(ZR, y)
            #print("T_pk:", T_pk)
            dpk1_E = (y_group * ek[0], y_group * ek[1]) + T_pk_dot
            #print("dpk1:",type(dpk1_E))
            #for exp in dpk1_E:
            #    print("exp:",type(exp))
            #    print("exp:",exp[0])
            dpk1 = np.array([PP['g2'] ** exp for exp in dpk1_E])
            ser = b''
            for out in T_pk:
                #print("out",out)
                for ele in out:
                    #print("ele",type(ele))
                    ser += self.groupG.serialize(ele)
            #T_pk_ser = T_pk_str[0] + T_pk_str[1]
            dpk2 = self.aone.Enc(APP, pk, skpk[user][1], self.user_list, ser)
            dk[user] = {'dpk1':dpk1, 'dpk2':dpk2}
        return ct, dk


    def Dec(self, ct, dk, y, PP, log_range, ekpk, label="l"):
        share = self.groupG.init(G1,0)
        for user in self.user_list:
            #print("share:",dk[user]['dpk2']['share'])
            share += dk[user]['dpk2']['share']

        Sig_dpk1 = np.array([self.groupG.init(G2, 0) for _ in range(2)])
        #print("Sig_dpk1",Sig_dpk1)
        Sig_Tpk = np.array([[0,0],[0,0]])
        #print("hree")
        for user in self.user_list:
            #print("dpk1:",dk[user]['dpk1'])
            Sig_dpk1 += dk[user]['dpk1']
            #print("hree2")
            DTpk = self.aone.Dec(dk[user]['dpk2'], share)
            DTpk = DTpk.decode()
            #print("DTpk",DTpk)
            DTpk2array = [0,0,0,0]
            for i in range(4):
                #print(i, len(DTpk),len(DTpk) // 4)
                per = len(DTpk) // 4
                temp = str(DTpk)[per * i : (per * i) + per]
                #print("temp",temp)
                DTpk2array[i] = self.groupG.deserialize(temp.encode())
                #print("temp_des",type(temp_des))
            DDTpk = np.array([[DTpk2array[0],DTpk2array[1]],[DTpk2array[2],DTpk2array[3]]])
            #print("DDTpk",DDTpk)
            Sig_Tpk = Sig_Tpk + DDTpk
        #for user in self.user_list:
        print("Sig_Tpk", type(Sig_Tpk), Sig_Tpk)
        vy = PP['H2'](str(y))
        Sig_Tpk_dot = Sig_Tpk.dot(vy)
        #print("len",len(Sig_Tpk_dot))
        d2right = np.array([PP['g2'] ** exp for exp in Sig_Tpk_dot])
        d2left = Sig_dpk1
        d2 = d2left / d2right
        print("d2",d2)
        Sig_cpk = 1
        for user in self.user_list:
            a = pair(ct[user], PP['g2'] ** y)
            Sig_cpk *= a
        print("Sig_cpk:", Sig_cpk)
        ul = PP['H1'](label)
        result = Sig_cpk / (pair(PP['g1'] ** ul[0],d2[0]) * pair(PP['g1'] ** ul[1],d2[1]))
        return result
