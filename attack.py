import numpy as np


class PhysicalAttack:
    """
    This class represents attack to perform using physical parameters of a device
    """

    """ Input file locations """
    __FILES: dict = {
        'input': r'data/inputs5.dat',
        't': r'data/T5.dat'
    }

    """ Input file contents """
    data: dict = {
        'input': [],
        't': []
    }

    def __init__(self):
        self.read_data()

    def read_data(self):
        """ Read input data """
        with open(self.__FILES['input']) as file:
            self.data['input'] = np.array([int(num.strip()) for num in file.read().split(',')])

        with open(self.__FILES['t']) as file:
            self.data['t'] = np.array([[float(num) for num in line.strip().split(',')] for line in file.readlines()])

    def dump_data(self):
        """ Print out the data for debugging purposes """
        print(self.data['input'])
        print(self.data['t'])


if __name__ == '__main__':
    physicalAttack = PhysicalAttack()
    physicalAttack.dump_data()
