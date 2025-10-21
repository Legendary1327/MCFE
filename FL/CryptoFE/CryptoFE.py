'''
[1] X. Qian, H. Li, M. Hao, S. Yuan, X. Zhang, and S. Guo,
“CryptoFE: Practical and Privacy-Preserving Federated Learning via Functional Encryption,”
in GLOBECOM 2022 - 2022 IEEE Global Communications Conference, Dec. 2022, pp. 2999–3004. doi: 10.1109/GLOBECOM48099.2022.10001080.
'''

from charm.toolbox.integergroup import RSAGroup, integer
import math, random

class CryptoFE():
    def __init__(self):
        group = RSAGroup()
        self.groupR = group
        self.all_para = {}

    def integer_sqrt(self, num):
        """
        Calculates the integer square root of a large integer n.
        Returns floor(sqrt(n)).
        """
        if num < 0:
            raise ValueError("isqrt() argument must be non-negative")
        if num == 0:
            return 0
        # Use bit length for a very good initial guess
        x = 1 << (int(num).bit_length() + 1) // 2
        # Newton's method for finding the root
        while True:
            y = (x + num // x) // 2
            if y >= x:
                return x
            x = y

    def Setup(self, user_number, m, n, secparam=1024):
        p, q, N = self.groupR.paramgen(secparam)
        N2 = N ** 2
        g_prime = self.groupR.random(N2) # g_prime
        N_bit_len = int(N).bit_length()
        log2_N = N_bit_len
        log2_sigma_lower_bound = 0.5 * math.log2(secparam) + 2.5 * log2_N
        sigma_bit_length = math.ceil(log2_sigma_lower_bound) + 1
        sigma = integer(2) ** sigma_bit_length
        #print(f"Calculated σ (sigma) to be a charm.integer of approx. {sigma.bit_length()} bits.")
        bound_s = 6 * sigma
        # random.randint 不接受 charm 的 integer，所以需要先转换回 Python int
        bound_s_py = int(bound_s)
        #s = [[3 for _ in range(n)] for _ in range(m)]
        s = [[integer(random.randint(-bound_s_py, bound_s_py)) for _ in range(n)] for _ in range(m)]
        #print(s)
        # 提取 s 的列向量 s_i

        si = [[0 for _ in range(n)] for _ in range(m)]
        for j in range(m):
            for i in range(n):
                si[j][i] = s[j][i]

        g = (g_prime ** (2 * N)) % N2
        #print(g)
        hij = [[0 for _ in range(n)] for _ in range(m)]
        for j in range(m):
            for i in range(n):
                hij[j][i] = (g ** si[j][i]) % N2
        inner_term = int(N) // (2 * n * m)
        #print(inner_term)
        #sqrt_val = math.(inner_term)
        sqrt_val = self.integer_sqrt(inner_term)
        #print(sqrt_val)
        #print(sqrt_val * sqrt_val)
        X = sqrt_val - 1
        Y = sqrt_val - 1
        print("Public Para: N:",N, "p,q:",p,q,"X,Y:",X,Y)
        pp = {"hij":hij, "X":X, "Y":Y, "m":m, "n":n, "N":N, "N2":N2, "g":g}
        return pp, s


    def KeyGen(self, pp, s):
        s_hat = [[self.groupR.random(pp["N"]) for _ in range(pp["n"])] for _ in range(pp["m"])]
        si_hat = [[0 for _ in range(pp["n"])] for _ in range(pp["m"])]
        for j in range(pp["m"]):
            for i in range(pp["n"]):
                si_hat[j][i] = s_hat[j][i]
        msk = {"s":s, "s_hat":s_hat}
        ski = si_hat
        return msk, ski

    def Enc(self, pp, ski, xi, user):
        hi = []
        for j in range(pp["m"]):
            hi.append(pp["hij"][j][user])
        wi = []
        for j in range(pp["m"]):
            wi.append(xi + integer(ski[j][user]))

        ri_bound = int(pp["N"]) // 4
        ri = random.randint(0, int(ri_bound))

        cti0 = pp["g"] ** ri % pp["N2"]
        cti1 = 1
        for j in range(pp["m"]):
            term_A = 1 + (integer(wi[j]) * pp["N"])
            #print(1,(term_A))
            term_B = (hi[j] ** ri)
            #print(2,term_B)
            iteration_product = (term_A * integer(term_B)) % pp["N2"]
            #print(3,(term_A * int(term_B)))
            cti1 *= integer(iteration_product)
        cti = {"cti0":cti0, "cti1":cti1}
        return cti


    def ASKeyDer(self, pp, msk, y, user_list):
        sky = 0
        for j in range(pp["m"]):
            siyi = 0
            for i in range(pp["n"]):
                siyi += (integer(msk["s_hat"][j][i]) * y[i])
            sky += siyi
        skyi = {}
        for i in range(pp["n"]):
            siyi2 = 0
            for j in range(pp["m"]):
                siyi2 += (msk["s"][j][i] * y[i])
            skyi[i] = siyi2
        #print("msk['s']",msk["s"])
        #print("skyi",skyi)
        ask = {"sky": sky, "skyi":skyi}
        return ask


    def Dec(self, pp, y, ask, cti):

        Cnp1 = 1 - (ask["sky"] * pp["N"])
        Ci = 1
        for i in range(pp["n"]):
            Cij = 1
            for j in range(pp["m"]):
                term1 = (cti[i]["cti1"] ** y[i])
                cti0_pow_skyi = (cti[i]["cti0"] ** ask["skyi"][i]) % pp["N2"]
                term2 = pow(cti0_pow_skyi, -1)
                Cij *= (term1 * integer(term2))
            Ci *= Cij
        Ci *= Cnp1
        D = (int((Ci - 1) % pp["N2"]) / pp["N"])
        print("Result:", D)
