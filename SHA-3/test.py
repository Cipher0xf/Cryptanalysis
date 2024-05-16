import keccak as K

msg = K.state
K.keccak_f_1600(msg)

# @staticmethod
# def prng_seed(seed):
#     for i in range(25):
#         if i < 12:
#             Keccak.state[i] = seed & 0xff
#             seed = seed >> 8
#         else:
#             Keccak.state[i] = 0
#      return 0
#
# @staticmethod
# def prng():
#     Keccak.state = Keccak.keccak_f_1600(Keccak.state)
#     rng = ''
#     for i in range(12):
#         rng += (bin(Keccak.state[i])[2:]).zfill(8)
#     return rng
#
# @staticmethod
# def randint(a, b):
#     b_blen = len(bin(b)) - 2
#     rng = Keccak.prng()
#     rng1 = int(rng[0:b_blen], 2)
#     while rng1 < a or rng1 > b:
#         rng = Keccak.prng()
#         rng1 = int(rng[0:b_blen], 2)
#     return rng1
#
# @staticmethod
# def hexdigest(state):
#     digest = ''
#     for i in range(len(state)):
#         digest += hex(state[i]).lstrip('0x').rstrip('L').zfill(2)
#     return digest
