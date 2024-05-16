class Keccak:
    state = [0] * 25

    @staticmethod
    def keccak_f_1600(state):
        KeccakLane = 64
        maxNrRounds = 4
        nrLanes = 25

        index = lambda x, y: ((x) % 5) + 5 * ((y) % 5)
        ROL64 = lambda a, offset: ((a << offset) & 0xffffffffffffffff) ^ (
                a >> (KeccakLane - offset)) if offset != 0 else a  # left-cyclic-rotate

        # 25 = 5*5 KeccakRotationOffset
        KeccakRhoOffsets = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
                            14]
        # 24 = 12+2*6 KeccakRoundConstant
        KeccakRoundConstants = [0x0000000000000001,
                                0x0000000000008082,
                                0x800000000000808a,
                                0x8000000080008000,
                                0x000000000000808b,
                                0x0000000080000001,
                                0x8000000080008081,
                                0x8000000000008009,
                                0x000000000000008a,
                                0x0000000000000088,
                                0x0000000080008009,
                                0x000000008000000a,
                                0x000000008000808b,
                                0x800000000000008b,
                                0x8000000000008089,
                                0x8000000000008003,
                                0x8000000000008002,
                                0x8000000000000080,
                                0x000000000000800a,
                                0x800000008000000a,
                                0x8000000080008081,
                                0x8000000000008080,
                                0x0000000080000001,
                                0x8000000080008008]

        # 初始化
        for x in range(5):
            for y in range(5):
                state[index(x, y)] = state[index(x, y)] & 0xffffffffffffffff
        A = state

        for indexRound in range(maxNrRounds):

            # θ step
            C = [0] * 5
            D = [0] * 5

            for x in range(5):
                for y in range(5):
                    C[x] ^= A[index(x, y)]

            for x in range(5):
                D[x] = ROL64(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5]

            for x in range(5):
                for y in range(5):
                    A[index(x, y)] ^= D[x]

            # ρ step
            for x in range(5):
                for y in range(5):
                    A[index(x, y)] = ROL64(A[index(x, y)], KeccakRhoOffsets[index(x, y)])

            # π step
            tempA = [0] * nrLanes

            for x in range(5):
                for y in range(5):
                    tempA[index(x, y)] = A[index(x, y)]

            for x in range(5):
                for y in range(5):
                    A[index(y, 2 * x + 3 * y)] = tempA[index(x, y)]

            # χ step
            C = [0] * 5;

            for y in range(5):
                for x in range(5):
                    C[x] = A[index(x, y)] ^ ((2 ** KeccakLane - 1 - A[index(x + 1, y)]) & A[index(x + 2, y)])
                for x in range(5):
                    A[index(x, y)] = C[x]

            # ι step
            A[index(0, 0)] ^= KeccakRoundConstants[indexRound]

        # for x in range(5):
        #     for y in range(5):
        #         print(A[index(x, y)], end=" ")
        #     print("\n")

        return A

    @staticmethod
    def sha3_512(string):
        r = 576
        c = 1024

        Keccak.state = [0] * 25
        index = lambda x, y: ((x) % 5) + 5 * ((y) % 5)
        load64 = lambda b: sum((int(hex(ord(b[i])), 16) << (8 * i)) for i in range(8))
        store64 = lambda a: list((a >> (8 * i)) % 256 for i in range(8))

        # Padding, using 10*1 strategy
        num_bytes = len(string)
        q = 72 - num_bytes % 72

        if q == 1:
            string += chr(0x86)
        elif q == 2:
            string += (chr(0x06) + chr(0x80))
        else:
            string += chr(0x06)
            for i in range(q - 2):
                string += chr(0x00)
            string += chr(0x80)

        # Absorbing phase
        for i in range(0, len(string), 72):
            tmp = string[i:i + 72] + chr(0x00) * 128  # 1600-bits (200-bytes) one dimensional data for state
            ########################################
            # print 'input: {x}'.format(x = i/72)
            # print [hex(ord(s)) for s in tmp]
            ########################################

            # convert 1600-bits tmp to 5*5 state[x][y] and added
            for j in range(5):
                for k in range(5):
                    Keccak.state[index(j, k)] ^= load64(
                        tmp[8 * index(j, k):8 * index(j, k) + 8])  # XOR 64-bit data each time
            # print [hex(s) for s in keccak.state]
            Keccak.state = Keccak.keccak_f_1600(Keccak.state)
            ########################################
            tmp = [0] * 200
            for i in range(5):
                for j in range(5):
                    tmp[8 * index(i, j):8 * index(i, j) + 8] = store64(Keccak.state[index(i, j)])  # a list of 8 bytes
            # print 'output:'
            # print [hex(s) for s in tmp[0:64]]
            ########################################

        # Squeezing phase, truncated the first 512 bits (64 bytes) of state
        # covert 3D state to 1D array
        tmp = [0] * 200
        for i in range(5):
            for j in range(5):
                tmp[8 * index(i, j):8 * index(i, j) + 8] = store64(Keccak.state[index(i, j)])  # a list of 8 bytes

        return tmp[0:64]
