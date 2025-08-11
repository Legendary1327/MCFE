'''
A Construction of All-or-Nothing Encapsulation from Bilinear Maps
[1] J. Chotard, E. Dufour-Sans, R. Gay, D. H. Phan, and D. Pointcheval, “Dynamic Decentralized Functional Encryption,” 2020, 2020/197. [Online]. Available: https://eprint.iacr.org/2020/197.
'''

import time
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, extract_key
from analysis.tools.sym_enc import *
from charm.toolbox.msp import MSP
from copy import *

class AoNE():
    def __init__(self, user_list):
        self.groupG = PairingGroup('SS512')
        self.util = MSP(self.groupG, False)
        self.user_list = user_list
        self.all_para = {}
        #print(miuj * kd)

    def Setup(self):

        self.AH = lambda x: self.groupG.hash(str(x), G1)
        g1 = self.groupG.random(G1)
        g2 = self.groupG.random(G2)
        PP = {'AH':self.AH,'g1':g1, 'g2':g2}
        #MSK = {'a':a, 'b':b, 'alpha':alpha}
        return PP

    def KeyGen(self,PP):
        tpk = self.groupG.random(ZR)
        g2tpk = PP['g2'] ** tpk
        return  g2tpk, tpk


    def Enc(self, PP, g2tpk, tpk, user_list, x_i):
        gpk = 1
        for user in user_list:
            gpk *= g2tpk[user]
        #for user in user_list:
        hashx = PP['AH'](user_list)
        rpk = self.groupG.random(ZR)
        SE_key = pair(hashx, gpk ** rpk)
        grpk = PP['g2'] ** rpk
        cpk = symmetric_encrypt(x_i, SE_key)
        share = hashx ** tpk
        ct = {'SE_key':SE_key, 'cpk':cpk, 'share':share, 'grpk':grpk}
        return ct


    def Dec(self, ct, share):
        #print("AONEDEC")
        SE_key = pair(share, ct['grpk'])
        if SE_key == ct['SE_key']:
            #print("AoNE decrypt success!")
            pass
        result = symmetric_decrypt(ct['cpk'], SE_key)
        return result
