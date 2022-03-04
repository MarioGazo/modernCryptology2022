"""
Assignment 2 for 02255 Modern Cryptology Spring 2022 at DTU
DPA attack on AES encryption algorithm

Authors:
    - Mário Gažo (s212698@student.dtu.dk)
    - Paul Gerard R Seghers (s191675@student.dtu.dk)
"""
from numpy import array, zeros
from math import sqrt


class PhysicalAttack:
    """
    Attacks AES block cypher using physical parameters of the device
    """

    """ Input file locations """
    __IN_file: str = r'data/inputs5.dat'
    __T_file: str = r'data/T5.dat'

    """ Input file contents """
    __IN: array
    __T: array

    """ AES S-Box """
    __S: list = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    """ H table """
    __H: array = zeros([256, 600])

    """ Correlation coefficients """
    __C: array = zeros([256, 55])

    """ Most probable key byte and it's probability """
    __key: tuple = (0, 0)

    def __read_data(self) -> None:
        """ Read input data """

        # Read the file with the AES inputs
        with open(self.__IN_file) as file:
            self.__IN = array([int(num.strip()) for num in file.read().split(',')])

        # Read the file with the AES traces for the inputs
        with open(self.__T_file) as file:
            self.__T = array(
                [[float(num) for num in line.strip().split(',')] for line in file.readlines()]
            ).transpose()

    def __construct_h(self) -> None:
        """ Construct the H table """

        def __hamming(byte) -> int:
            """ Calculate the Hamming weight (the amount of 1s) of a byte """
            if 0 > byte > 255:
                raise Exception("The byte has to be in <0,255>")

            return sum([byte & (1 << x) > 0 for x in range(8)])

        # Go through all the inputs and mix then with all the possible keys
        for i, item in enumerate(self.__IN):
            for j in range(256):
                self.__H[j][i] = __hamming(self.__S[item ^ j])

    def __correlation(self) -> None:
        """ Calculate the correlation between H and T rows """

        def __pearson(h: array, t: array) -> float:
            """ Pearson correlation coefficient calculation """
            if len(h) != len(t):
                raise Exception("The samples have to be of the same length")

            # Get means
            avg_h, avg_t = h.mean(), t.mean()

            # Split the formula into multiple sub-problems
            nom = sum([(x - avg_h) * (y - avg_t) for (x, y) in zip(h, t)])
            denom_h = sum([pow(x - avg_h, 2) for x in h])
            denom_t = sum([pow(x - avg_t, 2) for x in t])

            # Mix the sub-problems
            return nom / sqrt(denom_h * denom_t)

        # Go through the rows and find correlation
        for j, row_H in enumerate(self.__H):  # 256
            for i, row_T in enumerate(self.__T):  # 55
                self.__C[j][i] = __pearson(row_H, row_T)

    def __calculate_result(self):
        """ Get the result based on the correlation coefficients """

        # Find the most probable byte
        self.__C = self.__C.transpose()
        for row in self.__C:
            max_value = max(row)
            # Uncomment to see al the most probable key for each sample
            # print((list(row).index(max_value), max_value))
            if max_value > self.__key[1]:
                self.__key = (list(row).index(max_value), max_value)

    def get_key(self) -> tuple:
        """ Performs the DPA attack and returns the most probable key byte """
        self.__read_data()
        self.__construct_h()
        self.__correlation()
        self.__calculate_result()
        return self.__key
