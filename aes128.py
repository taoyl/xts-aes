"""
AES128 ECB mode implementation
By Nero Tao
"""

#--------------------------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------------------------
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

INV_SBOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]


MIXC_ARRAY = [
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02
]

INV_MIXC_ARRAY = [
    0X0E, 0X0B, 0X0D, 0X09,
    0X09, 0X0E, 0X0B, 0X0D,
    0X0D, 0X09, 0X0E, 0X0B,
    0X0B, 0X0D, 0X09, 0X0E
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# polynomial m(x)= x^8 + x^4 + x^3 + x + 1
AES_MX_POLY = 0x1B

AES_BLK_BYTES = 16
AES_ROUNDS = 10


#--------------------------------------------------------------------------------------------------
# Common functions
#--------------------------------------------------------------------------------------------------
def byteseq2starrseq(x:bytes):
    """
    Reorder byte sequence to state array sequence.
       input bytes               state array arrangement
    -----------------------------------------------------
    in0  in1  in2  in3           in0  in4  in8  in12
    in4  in5  in6  in7     ==>   in1  in5  in9  in13
    in8  in9  in10 in11          in2  in6  in10 in14
    in12 in13 in14 in15          in3  in7  in11 in15
    -----------------------------------------------------
    """
    y = [0]*16
    for i in range(4):
        for j in range(4):
            y[i+j*4] = x[i*4+j]
    return bytes(y)


def starrseq2byteseq(x:bytes):
    y = [0]*16
    for i in range(4):
        for j in range(4):
            y[4*i+j] = x[i+4*j]
    return bytes(y)


def add_round_key(text_in:bytes, key:bytes):
    assert(len(text_in) == len(key) == AES_BLK_BYTES)
    result = [text_in[i] ^ key[i] for i in range(AES_BLK_BYTES)]
    return bytes(result)


def byte2bin(x):
    x = x[0] if isinstance(x, bytes) else x & 0xFF
    return [int(i) for i in bin(x)[2:].zfill(8)[::-1]]


def xtime(x:int):
    x = x[0] if isinstance(x, bytes) else x 
    msb = x & 0x80
    y = (x << 1) & 0xFF
    return y ^ AES_MX_POLY if msb else y


def galois_mul(left:int, right:int):
    """Calculate Galois multiplication of left * right"""
    # calculate xtime value list
    xtime_list =[left,]
    _ = [xtime_list.append(xtime(xtime_list[i-1])) for i in range(1, 8)]
    # print(xtime_list)

    # calculate galois multiplication
    r_bits = byte2bin(right)
    mul_res = 0
    for i in range(8):
        if r_bits[i]:
            mul_res ^= xtime_list[i]
    return mul_res


def g_function(key:bytes, round:int):
    assert(len(key) == 4)
    temp = [x for x in key]
    # recuirsively left shift by 1 byte
    temp[:] = *temp[1:4], temp[0]
    temp_bytes = sub_bytes(bytes(temp))
    temp = [temp_bytes[i] ^ RCON[round] if i == 0 else temp_bytes[i] for i in range(4)]
    return bytes(temp)


def gen_round_key(key:bytes, round:int):
    # reorder byte back to get four words
    w0 = [key[0], key[4], key[8], key[12]]
    w1 = [key[1], key[5], key[9], key[13]]
    w2 = [key[2], key[6], key[10], key[14]]
    w3 = [key[3], key[7], key[11], key[15]]
    out_w0 = [x ^ y for x, y in zip(w0, g_function(bytes(w3), round))]
    out_w1 = [x ^ y for x, y in zip(w1, out_w0)]
    out_w2 = [x ^ y for x, y in zip(w2, out_w1)]
    out_w3 = [x ^ y for x, y in zip(w3, out_w2)]
    # remember reorder back for latter add_round_key
    return byteseq2starrseq(bytes(out_w0 + out_w1 + out_w2 + out_w3))

def gen_key_schedule(key:bytes):
    # w0-w3: the original key as just a placeholder
    w = [[key[0], key[4], key[8], key[12]],
         [key[1], key[5], key[9], key[13]],
         [key[2], key[6], key[10], key[14]],
         [key[3], key[7], key[11], key[15]],]
    for i in range(1, AES_ROUNDS+1):
        next_w0 =[x ^ y for x, y in zip(w[i*4-4], g_function(bytes(w[i*4-1]), i))]
        next_w1 = [x ^ y for x, y in zip(w[i*4-3], next_w0)]
        next_w2 = [x ^ y for x, y in zip(w[i*4-2], next_w1)]
        next_w3 = [x ^ y for x, y in zip(w[i*4-1], next_w2)]
        w += [next_w0, next_w1, next_w2, next_w3]

    return w


def get_key_from_ksch(w, round):
    """Get the key with state array from the key schedule words"""
    words_int = [y for x in w[round*4:(round+1)*4] for y in x]
    return byteseq2starrseq(bytes(words_int))
    

def _mix_col(mix_arr, x:bytes):
    # matrix multiplication: MIXC_ARRAY * x
    # use XOR as the addition in finite field
    y = [0] * 16
    for i in range(4):
        for j in range(4):
            y[4*i+j] = galois_mul(mix_arr[4*i+0], x[j+0]) ^ \
                       galois_mul(mix_arr[4*i+1], x[j+4]) ^ \
                       galois_mul(mix_arr[4*i+2], x[j+8]) ^ \
                       galois_mul(mix_arr[4*i+3], x[j+12])
    return bytes(y)

def _sbox(box, x:bytes):
    sbytes = [box[x[i]] for i in range(len(x))]
    return bytes(sbytes)



#--------------------------------------------------------------------------------------------------
# Cipher functions
#--------------------------------------------------------------------------------------------------
def sub_bytes(x:bytes):
    return _sbox(box=SBOX, x=x)


def mix_columns(x:bytes):
    return _mix_col(mix_arr=MIXC_ARRAY, x=x)


def shift_rows(x:bytes):
    assert(len(x) == AES_BLK_BYTES)
    temp = [y for y in x]
    # keep [0:4] unchanged
    # left shift by 1 byte
    temp[4:8] = *temp[5:8], temp[4]
    # left shift by 2 byte
    temp[8:12] = *temp[10:12], *temp[8:10]
    # left shift by 3 byte
    temp[12:16] = temp[15], *temp[12:15]
    return bytes(temp)


def aes128_encryption(plaint_text:bytes, key:bytes):
    assert(len(plaint_text) == len(key) == AES_BLK_BYTES)
    #1. the first AddRoundKey, no reorder to both plaint text and key, just do bytewise xor
    ptext_bytes = add_round_key(text_in=plaint_text, key=key)

    #2. reorder plaint text and key to convert state array
    ptext_starr = byteseq2starrseq(ptext_bytes)
    key_starr = byteseq2starrseq(key)
    #print(f'0-round: ct={ptext.hex()}, skey={skey.hex()}')

    #3. iterate 10 rounds
    for r in range(1, AES_ROUNDS+1):
        # print(f'AES encryption round{i} ...')
        ptext_starr = sub_bytes(ptext_starr)
        # print(f'{i}-round: sub_bytes={ptext_starr.hex()}')
        ptext_starr = shift_rows(ptext_starr)
        # print(f'{i}-round: shift_rows={ptext_starr.hex()}')
        if r < AES_ROUNDS:
            ptext_starr = mix_columns(ptext_starr)
        # print(f'{i}-round: mix_columns={ptext_starr.hex()}')
        key_starr = gen_round_key(key=key_starr, round=r)
        # print(f'{i}-round: key={key_starr.hex()}')
        ptext_starr = add_round_key(text_in=ptext_starr, key=key_starr)
        # print(f'{i}-round: final ct={ptext_starr.hex()}')

    return starrseq2byteseq(ptext_starr)


#--------------------------------------------------------------------------------------------------
# InvCipher functions
#--------------------------------------------------------------------------------------------------
def inv_sub_bytes(x:bytes):
    return _sbox(box=INV_SBOX, x=x)


def inv_mix_columns(x:bytes):
    return _mix_col(mix_arr=INV_MIXC_ARRAY, x=x)


def inv_shift_rows(x:bytes):
    assert(len(x) == AES_BLK_BYTES)
    temp = [y for y in x]
    # keep [0:4] unchanged
    # right shift by 1 byte
    temp[4:8] = temp[7], *temp[4:7]
    # right shift by 2 byte
    temp[8:12] = *temp[10:12], *temp[8:10]
    # right shift by 3 byte
    temp[12:16] = *temp[13:16], temp[12]
    return bytes(temp)


def aes128_decryption(cipher_text:bytes, key:bytes):
    """
    AES decryption is a little different than encryption, see AES spec section 5.3 for details
    """
    assert(len(cipher_text) == len(key) == AES_BLK_BYTES)

    #1. reorder cipher text and key to convert state array first
    # This is different than encryption because gen_key_schedule use state arrary sequence
    ctext_starr = byteseq2starrseq(cipher_text)
    key_starr = byteseq2starrseq(key)

    #2. compute key schedule first because decrytion starts with the last round key (w[40:44])
    ksch_words = gen_key_schedule(key=key_starr)

    #3. the first AddRoundKey with the last four words (w[40:44])
    key_starr = get_key_from_ksch(w=ksch_words, round=10)
    # print(f'ik_sch: {starrseq2byteseq(key_starr).hex()=}')
    ctext_starr = add_round_key(text_in=ctext_starr, key=key_starr)
    # print(f'istart: {starrseq2byteseq(ctext_starr).hex()=}')

    #4. iterate 10 rounds
    for r in range(AES_ROUNDS-1,-1,-1):
        # print(f'AES decryption round{r} ...')
        ctext_starr = inv_shift_rows(ctext_starr)
        # print(f'{r}-round: shift_rows={ctext_starr.hex()}')
        ctext_starr = inv_sub_bytes(ctext_starr)
        # print(f'{r}-round: sub_bytes={ctext_starr.hex()}')
        key_starr = get_key_from_ksch(w=ksch_words, round=r)
        # print(f'{r}-round: key={key_starr.hex()}')
        ctext_starr = add_round_key(text_in=ctext_starr, key=key_starr)
        # print(f'{r}-round: after add_round_key={ctext_starr.hex()}')
        if r > 0:
            ctext_starr = inv_mix_columns(ctext_starr)
        # print(f'{r}-round: mix_columns={ctext_starr.hex()}')

    return starrseq2byteseq(ctext_starr)


#--------------------------------------------------------------------------------------------------
# Test functions
#--------------------------------------------------------------------------------------------------
def main():
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # random test
    key = os.urandom(16)
    plaint_text = os.urandom(16)

    # Test vector1 from AES spec Appendix B
    # key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    # plaint_text = bytes.fromhex('3243f6a8885a308d313198a2e0370734')

    # Test vector2 from AES spec Appendix C.1
    # key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    # plaint_text = bytes.fromhex('00112233445566778899aabbccddeeff')

    print(f'Plaint text={plaint_text.hex()}, key={key.hex()}')

    cipher_std = Cipher(algorithms.AES(key), modes.ECB())
    enc_std = cipher_std.encryptor()
    ct_std = enc_std.update(plaint_text)
    print(f'Built-in Cipher text: {ct_std.hex()}')

    ct_custom = aes128_encryption(plaint_text=plaint_text, key=key)
    print(f'Custom Cipher text: {ct_custom.hex()}')

    if ct_custom.hex() != ct_std.hex():
        print('** Encryption Check FAILED!')
        print(f'cus:{ct_custom.hex()}')
        print(f'std:{ct_std.hex()}')
    else:
        print('Encryption Check PASS')

    
    cipher_text = ct_std
    pt_custom = aes128_decryption(cipher_text=cipher_text, key=key)
    print(f'Custom InvCipher text: {pt_custom.hex()}')

    cipher_std = Cipher(algorithms.AES(key), modes.ECB())
    dec_std = cipher_std.decryptor()
    pt_std = dec_std.update(cipher_text)
    print(f'Built-in InvCipher text: {pt_std.hex()}')

    if pt_custom.hex() != pt_std.hex():
        print('** Decryption Check FAILED!')
        print(f'cus:{pt_custom.hex()}')
        print(f'std:{pt_std.hex()}')
    else:
        print('Decryption Check PASS')


if __name__ == '__main__':

    # right = 0x13
    # left = 0x57
    # print(f'{hex(galois_mul(left, right))=}') 

    main()
