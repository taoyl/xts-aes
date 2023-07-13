"""
SM4 ECB mode implementation
By Nero Tao
"""

#--------------------------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------------------------
SBOX = [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
]

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

CK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
      0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
      0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
      0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
      0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
      0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
      0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
      0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

SM4_ROUNDS = 32


#--------------------------------------------------------------------------------------------------
# Common functions
#--------------------------------------------------------------------------------------------------
def sbox(x:int):
    x_bytes = [(x >> i*8) & 0xff for i in range(4)]
    x_sbox = [SBOX[b] for b in x_bytes]
    return x_sbox[0] | (x_sbox[1] << 8) | (x_sbox[2] << 16) | (x_sbox[3] << 24)


def clshift(x:int, n:int):
    """Cyclic left shift a 32-bit x by n bits"""
    x_bin = bin(x & 0xffffffff)[2:].zfill(32)
    # Note bin[0] is the MSB while bin[31] is the LSB in python str
    x_bin = x_bin[n:] + x_bin[0:n]
    return (int(x_bin, 2))


def gen_rk(k0, k1, k2, k3, round):
    """Generate round key"""
    sbox_in = k1 ^ k2 ^ k3 ^ CK[round]
    # print(f'{hex(k0)=}, {hex(k1)=}, {hex(k2)=}, {hex(CK[round])=}')
    sbox_out = sbox(sbox_in)
    # print(f'{hex(sbox_in)=}, {hex(sbox_out)=}')
    k4 = k0 ^ clshift(sbox_out, 13) ^ sbox_out ^ clshift(sbox_out, 23)
    return k4


def bytes2words(x:bytes):
    """Split 16 bytes into 4 words"""
    assert(len(x) == 16)
    return [int.from_bytes(x[i*4:(i+1)*4], 'big') for i in range(4)]


def int2bytes(x:int, byte_num):
    # 1 byte = 2 hex number, thus padding byte_num*2 leading-zero 
    return bytes.fromhex(hex(x)[2:].zfill(byte_num*2))


#--------------------------------------------------------------------------------------------------
# Encryption/Decryption functions
#--------------------------------------------------------------------------------------------------
def sm4ecb_encryption(text_in:bytes, key:bytes):
    assert(len(text_in) == len(key) == 16)

    x0, x1, x2, x3 = bytes2words(text_in)
    # print(f'{hex(x0)=}, {hex(x1)=}, {hex(x2)=}, {hex(x3)=}')
    
    # merge system parameter FK into key
    k0, k1, k2, k3 = [FK[i] ^ k for i, k in enumerate(bytes2words(key))]

    # 32-round iteration
    for r in range(SM4_ROUNDS):
        # print(f'SM4 encryption round{r} ...')
        # xor x1~x3 and rk
        k4 = gen_rk(k0, k1, k2, k3, round=r)
        sbox_in = x1 ^ x2 ^ x3 ^ k4
        sbox_out = sbox(sbox_in)
        x4 = x0 ^ clshift(sbox_out, 2) ^ clshift(sbox_out, 10) ^ sbox_out ^ clshift(sbox_out, 18) ^ clshift(sbox_out, 24)
        # print(f'rk[{r}]={hex(k4)}, x[{r}]={hex(x4)}')
        k0, k1, k2, k3 = k1, k2, k3, k4
        x0, x1, x2, x3 = x1, x2, x3, x4

    # convert int to bytes and reorder transform
    # x35, x34, x33, x32
    return int2bytes(x3, 4) + int2bytes(x2, 4) + int2bytes(x1, 4) + int2bytes(x0, 4)


def sm4ecb_decryption(text_in:bytes, key:bytes):
    assert(len(text_in) == len(key) == 16)

    x0, x1, x2, x3 = bytes2words(text_in)
    # print(f'{hex(x0)=}, {hex(x1)=}, {hex(x2)=}, {hex(x3)=}')
    
    #1. compute all round key first because decryption starts with the rk[31]
    # merge system parameter FK into key
    k0, k1, k2, k3 = [FK[i] ^ k for i, k in enumerate(bytes2words(key))]
    round_keys = [] 
    for r in range(SM4_ROUNDS):
        k4 = gen_rk(k0, k1, k2, k3, round=r)
        k0, k1, k2, k3 = k1, k2, k3, k4
        round_keys.append(k4)

    #2. 32-round iteration
    for r in range(SM4_ROUNDS):
        # print(f'SM4 decryption round{r} ...')
        # xor x1~x3 and rk[31-r]
        sbox_in = x1 ^ x2 ^ x3 ^ round_keys[31-r]
        sbox_out = sbox(sbox_in)
        x4 = x0 ^ clshift(sbox_out, 2) ^ clshift(sbox_out, 10) ^ sbox_out ^ clshift(sbox_out, 18) ^ clshift(sbox_out, 24)
        # print(f'rk[{r}]={hex(k4)}, x[{r}]={hex(x4)}')
        x0, x1, x2, x3 = x1, x2, x3, x4

    # convert int to bytes and reorder transform
    # x3, x2, x1, x0
    return int2bytes(x3, 4) + int2bytes(x2, 4) + int2bytes(x1, 4) + int2bytes(x0, 4)


if __name__ == '__main__':
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # random test
    key = os.urandom(16)
    plaint_text = os.urandom(16)

    # Test vector from spec
    # plaint_text = bytes.fromhex('0123456789abcdeffedcba9876543210')
    # key = bytes.fromhex('0123456789abcdeffedcba9876543210')

    print(f'plaint text={plaint_text.hex()}, key={key.hex()}')

    cipher = Cipher(algorithms.SM4(key), modes.ECB())
    enc = cipher.encryptor()
    ct_std = enc.update(plaint_text)
    print(f'{ct_std.hex()=}')

    ct_cus = sm4ecb_encryption(text_in=plaint_text, key=key)
    print(f'{ct_cus.hex()=}')
    if ct_std.hex() != ct_cus.hex():
        print('** Encryption Check FAILED!')
        print(f'cus:{ct_cus.hex()}')
        print(f'std:{ct_std.hex()}')
    else:
        print('Encryption Check PASS')

    cipher = Cipher(algorithms.SM4(key), modes.ECB())
    dec = cipher.decryptor()
    pt_std = dec.update(ct_std)
    print(f'{pt_std.hex()=}')

    pt_cus = sm4ecb_decryption(text_in=ct_std, key=key)
    print(f'{pt_cus.hex()=}')
    if (pt_std.hex() != pt_cus.hex()) or (pt_cus != plaint_text):
        print('** Encryption Check FAILED!')
        print(f'cus:{pt_cus.hex()}')
        print(f'std:{pt_std.hex()}')
    else:
        print('Decryption Check PASS')