"""
Assignment 2 for 02255 Modern Cryptology Spring 2022 at DTU
DPA attack on AES encryption algorithm

Authors:
    - Mário Gažo (s212698@student.dtu.dk)
    - Paul Gerard R Seghers (s191675@student.dtu.dk)
"""
from src.PhysicalAttack import PhysicalAttack

if __name__ == '__main__':
    physicalAttack = PhysicalAttack()
    key = physicalAttack.get_key()
    print(f"Key byte: {hex(key[0])} ({key[0]})")
    print(f"Probability: {round(key[1] * 100)}%")
