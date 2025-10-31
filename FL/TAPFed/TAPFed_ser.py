'''
[1] R. Xu et al.,
“TAPFed: Threshold Secure Aggregation for Privacy-Preserving Federated Learning,”
IEEE Transactions on Dependable and Secure Computing, vol. 21, no. 5, pp. 4309–4323, 2024, doi: 10.1109/TDSC.2024.3350206.
'''

import time, os
from charm.toolbox.integergroup import IntegerGroup, integer, isPrime

class TAPFed_ser():
    def __init__(self, sec_param=512):
        self.groupI = IntegerGroup()
        self.storage_path = "./data_storage"  # ???????
        os.makedirs(self.storage_path, exist_ok=True)
        self.all_g = {}
        self.create_or_load_elements(sec_param)
        self.shift = 5
        # self.fixedSeed = self.groupG.random(ZR)
        # self.fixedSeed = 5

    def create_or_load_elements(self, sec_param):
        p_path = os.path.join(self.storage_path, "p.bin")
        q_path = os.path.join(self.storage_path, "q.bin")
        g_path = os.path.join(self.storage_path, "g.bin")
        table_path = os.path.join(self.storage_path, "all_g.txt")

        if os.path.exists(p_path) and os.path.exists(q_path) and os.path.exists(g_path) and os.path.exists(table_path):
            print("Loading g1, g2, and all_gt from disk...")
            with open(p_path, "rb") as f:
                self.p = self.groupI.deserialize(f.read())
            with open(q_path, "rb") as f:
                self.q = self.groupI.deserialize(f.read())
            with open(g_path, "rb") as f:
                self.g = self.groupI.deserialize(f.read())
            self.all_g = {}
            self.groupI.q = self.q
            self.groupI.p = self.p
            with open(table_path, "r") as f:
                for line in f:
                    key, val = line.strip().split(",")
                    self.all_g[key] = int(val)

            print("Loaded successfully.")
            return

        print("Creating new p, q, g, and table...")
        if sec_param == 666:
            self.q = 11657052578124076088082365974916365708508449116852416686189550139083537056567105966672587264721421621034255926684162152887753868775571269278186964083343303
            self.p = 23314105156248152176164731949832731417016898233704833372379100278167074113134211933345174529442843242068511853368324305775507737551142538556373928166686607

            self.groupI.r = 2
            self.groupI.setparam(self.p, self.q)

            ser_g = b'0:88:mGDMlcEA6vctyx5v6ip2sLOgzpMRB+tAZv0pPqgydPAuZQULKAmKObXnYByl+Tt87GGfj15NBJ/VZKfZvduQbQ==:88:Ab0k+OIF9qgMJvo+ORbzmRtYKko1KJTURCOrFGSFx2Kj7hB/4xxzsEM33gpvaJpvxlQHQuRV+hBzM/Dlg0KR/48=:'
            self.g = self.groupI.deserialize(ser_g)
        else:
            while 1:
                self.groupI.paramgen(sec_param)
                self.q = self.groupI.q
                self.p = 2 * self.q + 1
                if isPrime(self.q) and isPrime(self.p):
                    break
            print("q:", isPrime(self.q), self.q)
            print("p:", isPrime(self.p), self.p)
            h = self.groupI.random(self.p)
            self.groupI.r = 2
            self.groupI.q = self.q
            self.groupI.p = self.p
            self.g = (h ** self.groupI.r) % self.p
            print("g:", self.groupI.serialize(self.g))

        table_time = time.time()
        print("Creating log table...")
        for i in range(0, 2000):
            self.all_g[str(self.g ** i)] = i
        print("Log table created in {:.3f} seconds".format(time.time() - table_time))

        with open(p_path, "wb") as f:
            f.write(self.groupI.serialize(self.p))
        with open(q_path, "wb") as f:
            f.write(self.groupI.serialize(self.q))
        with open(g_path, "wb") as f:
            f.write(self.groupI.serialize(self.g))

        with open(table_path, "w") as f:
            for k, v in self.all_g.items():
                f.write(f"{k},{v}\n")

        print("Saved p, q, g and all_g to disk.")


    def Setup(self, neta, t, s, n):

        print("self.g,", self.g)
        print("self.p,", self.p)
        '''
        n:client
        s:server(aggregator)
        '''

        alpha = self.groupI.random(self.p)
        W_ser = {}
        U_ser = {}
        for i in range(n):
            W_ser[i] = self.groupI.serialize(self.groupI.random(self.p))
            U_ser[i] = self.groupI.serialize(self.groupI.random(self.p))

        self.H = lambda x: self.groupI.hash(str(x))
        g_alpha = self.g ** alpha
        g_alpha_ser = self.groupI.serialize(g_alpha)
        self.test_alpha = alpha
        g_aw_ser = {}
        for i in range(n):
            g_aw_ser[i] = self.groupI.serialize(self.g ** (alpha * self.groupI.deserialize(W_ser[i])))

        pp = {'p_ser':self.groupI.serialize(self.p),'g_ser':self.groupI.serialize(self.g),'t':t,'s':s,'n':n,'H':self.H, 'neta':neta}
        msk = {'W_ser':W_ser, 'U_ser':U_ser, 'g_alpha_ser':g_alpha_ser, 'g_aw_ser':g_aw_ser}
        return pp, msk


    def SKDis(self, pp, msk, user_list):
        g_aw_eid_ser = {}
        for i in range(len(user_list)):
            g_aw_eid_ser[i] = {'pp':pp, 'g_alpha_ser':msk['g_alpha_ser'], 'g_aw_ser':msk['g_aw_ser'][i], 'U_ser':msk['U_ser'][i]}

        return g_aw_eid_ser


    def DKGen(self, pp, msk, y, server_list, l='l'):
        #shift = 5
        y = integer(y[0], self.p)
        yU = integer(0, self.p)

        bi0 = {}
        for i in range(pp['n']):
            yU += self.groupI.deserialize(msk['U_ser'][i]) * y
            bi0[i] = self.groupI.deserialize(msk['W_ser'][i]) * y

        a0 = self.H(l) * yU #% self.p

        self.test_bi0 = bi0
        self.test_a0 = a0
        self.test_two = integer(2, self.p)
        threshold = len(server_list)
        degree = threshold - 1

        coefficient_a = [a0] + [self.groupI.random(self.p) for _ in range(degree)]
        shares_a = []
        for j in range(len(server_list)):
            x = j + self.shift
            fx = self._evaluate_poly(coefficient_a, x) #% self.p
            shares_a.append((x, fx))
        shares_b = {}
        for i in range(pp['n']):
            coefficient_bi = [bi0[i]]  + [self.groupI.random(self.p) for _ in range(degree)]
            shares_b_temp = []
            for j in range(len(server_list)):
                x = j + self.shift
                fx = self._evaluate_poly(coefficient_bi, x)# % self.p
                shares_b_temp.append((x, fx))
            shares_b[i] = shares_b_temp

        dkdidx = {}
        for j in range(len(server_list)):
            vj0 = shares_a[j][1]
            vj1_temp = {}
            for i in range(pp['n']):
                vj1_temp[i] = shares_b[i][j][1]
            dkdidx[j] = {'pp':pp, 'vj0':vj0, 'vj1':vj1_temp}
        return dkdidx


    def Enc(self, ski, xi, test_id, l="l"):
        xi = integer(xi[0], self.p)
        cti0_exp = integer(self.H(l), self.p) * integer(self.groupI.deserialize(ski['U_ser']), self.p) + xi
        two = integer(2, self.p)
        cti0_left = self.groupI.deserialize(ski['pp']['g_ser']) ** (cti0_exp)

        ri = self.groupI.random(self.p)
        cti0_right = self.groupI.deserialize(ski['g_aw_ser']) ** ri
        cti0 = cti0_right * cti0_left #% self.p

        self.test_c0 = cti0
        cti1 = self.groupI.deserialize(ski['g_alpha_ser']) ** ri
        return {'cti0':(cti0), 'cti1':(cti1)}


    def ShareDec(self, pp, x_l2, y, dkj, server_list, all_ct, server_id):
        y = integer(y[0], self.p)
        ctj0p = integer(1, self.p)
        ctj1p = {}
        lan_coeff = self._get_coeff(server_list)
        self.test_coef = lan_coeff
        for i in range(pp['n']):
            ctj0p *= integer(all_ct[i]['cti0'], self.p) ** y
            ctj1p[i] = integer(all_ct[i]['cti1'] ** (dkj['vj1'][i] * integer(int(lan_coeff[server_id]))))
        ctj2p = integer(self.groupI.deserialize(pp['g_ser']) ** (dkj['vj0'] * integer(int(lan_coeff[server_id]))))
        return {'ctj0p':ctj0p ,'ctj1p':ctj1p,'ctj2p':ctj2p}


    def CombDec(self, pp, serv_ct_list):
        denominator_ij_left = integer(1, self.p)
        for i in range(pp['n']):
            denominator_j_left = integer(1, self.p)
            for j in range(pp['s']):
                denominator_j_left *= serv_ct_list[j]['ctj1p'][i] % self.p
            denominator_ij_left *= denominator_j_left
        numerator = serv_ct_list[2]['ctj0p'] % self.p
        denominator_j_right = integer(1, self.p)
        for j in range(pp['s']):
            denominator_j_right *= (serv_ct_list[j]['ctj2p']) % self.p
        denominator_ij_left %= self.p
        denominator_j_right %= self.p
        D = numerator / (denominator_ij_left * (denominator_j_right)) % self.p
        print(self.all_g[str(D)])


    def _evaluate_poly(self, poly_coeffs, x):
        """
        Evaluates a polynomial at a given point x in Z_p.
        :param poly_coeffs: A list of coefficients [a_0, a_1, ..., a_{t-1}] as charm integer objects.
        :param x: The point to evaluate at, also a charm integer object.
        :return: The result of the evaluation, f(x), as a charm integer object.
        """
        result = 0
        # Compute f(x) = a_0 + a_1*x + a_2*x^2 + ...
        for i in range(len(poly_coeffs)):
            if i == 0:
                result += integer(poly_coeffs[i])
            else:
                #term = poly_coeffs[i] * (x ** i)
                result += integer(poly_coeffs[i]) * (x ** i)
        return result


    def _reconstruct_secret(self, shares):
        """
        Reconstructs the secret from a list of shares using Lagrange Interpolation.
        The secret is the value of the polynomial at x=0.
        :param shares: A list of at least 't' shares, where each share is a tuple (x, y).
        :return: The reconstructed secret as a charm integer object.
        """
        if not isinstance(shares, list) or len(shares) == 0:
            raise ValueError("Shares must be a non-empty list.")
        # The secret is the sum of y_j * L_j(0) for all j
        secret = 0
        # Separate x and y coordinates from the shares
        points_x = [s[0] for s in shares]
        points_fx = [s[1] for s in shares]
        for j in range(len(shares)):
            j_t, fj_t = points_x[j], points_fx[j]
            numerator = 1
            denominator = 1
            for m in range(len(shares)):
                if m == j:
                    continue
                jp = points_x[m]
                numerator *= -jp
                denominator *= (j_t - jp)
                #print("j,m,jp,j_t",j,m,jp,j_t)
            # The Lagrange basis polynomial value at x=0
            # We need to compute the modular inverse of the denominator
            lagrange_poly_at_zero = numerator / denominator

            secret += integer(fj_t) * int(lagrange_poly_at_zero)
        return secret


    def _get_coeff(self, server_list):
        back_coeff = []
        points_x = []
        for j in range(len(server_list)):
            points_x.append(j + self.shift)
        for j in range(len(server_list)):
            j_t = points_x[j]
            numerator = 1
            denominator = 1
            for m in range(len(server_list)):
                if m == j:
                    continue
                jp = points_x[m]
                numerator *= -jp
                denominator *= (j_t - jp)
            lagrange_poly_at_zero = numerator / denominator
            back_coeff.append(lagrange_poly_at_zero)
        return back_coeff
