"""
AES-XTS implementation using python
By Nero Tao
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aes128 import aes128_decryption, aes128_encryption
from sm4 import sm4ecb_encryption, sm4ecb_decryption


GF_128_FDBK = 0x87
AES_BLK_BYTES = 16

def gf2_128(L:bytes, j:int):
    assert(len(L) == AES_BLK_BYTES)
    if j == 0:
        return L
    else:
        # multiple T by a^j: 128 bit block left shifts by 1
        cin = 0
        T = []
        for i in range(AES_BLK_BYTES):
            cout = (L[i] >> 7) & 0x1
            T.append((L[i] * 2 + cin) & 0xff)
            #print(f'{i=}, {cin=}, {cout=}, {hex(L[i])=}, {hex(T[i])=}')
            cin = cout
        # if bit[127] is 1, T[0] xor GF_128_FDBK
        if cin == 1:
            T[0] ^= GF_128_FDBK
        #print(f'{L.hex()=}, {bytes(T).hex()=}')
        return bytes(T)

def hex2bytes(h:str, byte_num=16):
    # h[0] is the least significant byte (lsb) and it is printed out at leftmost of a string
    # zfill pads 0 at left side, while we need to pad 0s at right side (MSB part), 
    # so reverse it before zero padding and reverse it back after padding
    return bytes.fromhex(h[::-1].zfill(byte_num*2)[::-1])

def aes128_ecb_enc(key:bytes, plaint_text:bytes):
    # option1: use cryptography lib
    # cipher = Cipher(algorithms.AES(key), modes.ECB())
    # enc = cipher.encryptor()
    # return enc.update(plaint_text)

    # option2: use custom development ase128
    return aes128_encryption(plaint_text=plaint_text, key=key)

def aes128_ecb_dec(key:bytes, cipher_text:bytes):
    # option1: use cryptography lib
    # cipher = Cipher(algorithms.AES(key), modes.ECB())
    # dec = cipher.decryptor()
    # return dec.update(cipher_text)

    # option2: use custom development ase128
    return aes128_decryption(cipher_text=cipher_text, key=key)

def sm4_ecb_enc(key:bytes, plaint_text:bytes):
    # option1: use cryptography lib
    # cipher = Cipher(algorithms.SM4(key), modes.ECB())
    # enc = cipher.encryptor()
    # return enc.update(plaint_text)

    # option2: use custom development ase128
    return sm4ecb_encryption(text_in=plaint_text, key=key)

def sm4_ecb_dec(key:bytes, cipher_text:bytes):
    # option1: use cryptography lib
    # cipher = Cipher(algorithms.SM4(key), modes.ECB())
    # dec = cipher.decryptor()
    # return dec.update(cipher_text)

    # option2: use custom development ase128
    return sm4ecb_decryption(text_in=cipher_text, key=key)


def xts_encdec(enc_mode:bool, key1:bytes, key2:bytes, data_unit_num:int, text_in:bytes, 
               enc_func=aes128_ecb_enc, dec_func=aes128_ecb_dec):
    """text_in must be the multiple of 16 bytes.
    key2 for tweak encryption and key1 for plaint text encryption
    """

    # test must be length of x16
    assert(len(text_in) % AES_BLK_BYTES == 0)

    # covert data_unit_num to tweak plaint text
    tweak_pt = b''
    for i in range(AES_BLK_BYTES):
        b = data_unit_num & 0xff
        tweak_pt += b.to_bytes(1, 'little')
        data_unit_num = data_unit_num >> 8

    print(f'{tweak_pt.hex()=}')
    # tweak encryption
    tweak_ct = enc_func(key2, tweak_pt)

    text_out = b''
    for j in range(len(text_in) >> 4):
        # adjust the tweak
        tweak_ct = gf2_128(tweak_ct, j)
        #print(f'{j=}, {tweak_ct.hex()=}')

        # merge tweak into input text
        block_text = [text_in[j*AES_BLK_BYTES + i] ^ tweak_ct[i] for i in range(AES_BLK_BYTES)]
        block_text = bytes(block_text)
        
        # encypt/decrypt
        pre_out = enc_func(key1, block_text) if enc_mode else dec_func(key1, block_text)

        # merge the tweak into the output block
        block_text_out = [pre_out[i] ^ tweak_ct[i] for i in range(AES_BLK_BYTES)]
        text_out += bytes(block_text_out)

    return text_out


def test_aes128_xts():
    # Note: for bytes, [0] is the least significant byte (lsb) and it is printed out at leftmost of a string
    key1 = os.urandom(16)
    key2 = os.urandom(16)
    tweak = os.urandom(16)
    plaint_text = os.urandom(16)
    
    # Test vectors from XTS-AES spec
    # Test vector1
    #key1 = hex2bytes('00000000000000000000000000000000')
    #key2 = hex2bytes('00000000000000000000000000000000')
    #tweak = int('0', 16)
    #plaint_text = bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    #golden_cipher_text = '917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e'
    
    # Test vector2
    key1  = hex2bytes('11111111111111111111111111111111')
    key2  = hex2bytes('22222222222222222222222222222222')
    tweak = int('3333333333', 16)
    plaint_text = bytes.fromhex('4444444444444444444444444444444444444444444444444444444444444444')
    golden_cipher_text = 'c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0'
    
    # Test vector3
    key1 = hex2bytes('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0')
    key2 = hex2bytes('22222222222222222222222222222222')
    tweak = int('3333333333', 16)
    plaint_text = bytes.fromhex('4444444444444444444444444444444444444444444444444444444444444444')
    golden_cipher_text = 'af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89'
    
    # Test vector4
    key1 = hex2bytes('27182818284590452353602874713526')
    key2 = hex2bytes('31415926535897932384626433832795')
    tweak = int('fd', 16)
    plaint_text = bytes.fromhex('8e41b78c390b5af9d758bb214a67e9f6bf7727b09ac6124084c37611398fa45d'
                                'aad94868600ed391fb1acd4857a95b466e62ef9f4b377244d1c152e7b30d731a'
                                'ad30c716d214b707aed99eb5b5e580b3e887cf7497465651d4b60e6042051da3'
                                '693c3b78c14489543be8b6ad0ba629565bba202313ba7b0d0c94a3252b676f46'
                                'cc02ce0f8a7d34c0ed229129673c1f61aed579d08a9203a25aac3a77e9db6026'
                                '7996db38df637356d9dcd1632e369939f2a29d89345c66e05066f1a3677aef18'
                                'dea4113faeb629e46721a66d0a7e785d3e29af2594eb67dfa982affe0aac058f'
                                '6e15864269b135418261fc3afb089472cf68c45dd7f231c6249ba0255e1e0338'
                                '33fc4d00a3fe02132d7bc3873614b8aee34273581ea0325c81f0270affa13641'
                                'd052d36f0757d484014354d02d6883ca15c24d8c3956b1bd027bcf41f151fd80'
                                '23c5340e5606f37e90fdb87c86fb4fa634b3718a30bace06a66eaf8f63c4aa3b'
                                '637826a87fe8cfa44282e92cb1615af3a28e53bc74c7cba1a0977be9065d0c1a'
                                '5dec6c54ae38d37f37aa35283e048e5530a85c4e7a29d7b92ec0c3169cdf2a80'
                                '5c7604bce60049b9fb7b8eaac10f51ae23794ceba68bb58112e293b9b692ca72'
                                '1b37c662f8574ed4dba6f88e170881c82cddc1034a0ca7e284bf0962b6b26292'
                                'd836fa9f73c1ac770eef0f2d3a1eaf61d3e03555fd424eedd67e18a18094f888')
    golden_cipher_text = ('d55f684f81f4426e9fde92a5ff02df2ac896af63962888a97910c1379e20b0a3'
                          'b1db613fb7fe2e07004329ea5c22bfd33e3dbe4cf58cc608c2c26c19a2e2fe22'
                          'f98732c2b5cb844cc6c0702d91e1d50fc4382a7eba5635cd602432a2306ac4ce'
                          '82f8d70c8d9bc15f918fe71e74c622d5cf71178bf6e0b9cc9f2b41dd8dbe441c'
                          '41cd0c73a6dc47a348f6702f9d0e9b1b1431e948e299b9ec2272ab2c5f0c7be8'
                          '6affa5dec87a0bee81d3d50007edaa2bcfccb35605155ff36ed8edd4a40dcd4b'
                          '243acd11b2b987bdbfaf91a7cac27e9c5aea525ee53de7b2d3332c8644402b82'
                          '3e94a7db26276d2d23aa07180f76b4fd29b9c0823099c9d62c519880aee7e969'
                          '7617c1497d47bf3e571950311421b6b734d38b0db91eb85331b91ea9f61530f5'
                          '4512a5a52a4bad589eb69781d537f23297bb459bdad2948a29e1550bf4787e0b'
                          'e95bb173cf5fab17dab7a13a052a63453d97ccec1a321954886b7a1299faaeec'
                          'ae35c6eaaca753b041b5e5f093bf83397fd21dd6b3012066fcc058cc32c3b09d'
                          '7562dee29509b5839392c9ff05f51f3166aaac4ac5f238038a3045e6f72e48ef'
                          '0fe8bc675e82c318a268e43970271bf119b81bf6a982746554f84e72b9f00280'
                          'a320a08142923c23c883423ff949827f29bbacdc1ccdb04938ce6098c95ba6b3'
                          '2528f4ef78eed778b2e122ddfd1cbdd11d1c0a6783e011fc536d63d053260637')

    # Test vector5
    # key1 = hex2bytes('00000000000000000000000000000000')
    # key2 = hex2bytes('00000000000000000000000000000000')
    # tweak = int('0', 16)
    # plaint_text = bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    # golden_cipher_text = '917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e734867fd279b516a094b9713c18e772953525a657c3fce194e9a43b452102fb1'
    
    print(f'plaint_text={plaint_text.hex()}')
    
    # built-in XTS algorithm, only support 128bit data unit (one block)
    # key = key1 + key2
    # cipher_xts = Cipher(algorithms.AES(key1+key2), modes.XTS(tweak))
    # enc_xts = cipher_xts.encryptor()
    # ct_xts = enc_xts.update(plaint_text_byte)
    # print(f'Built-in XTS: {ct_xts.hex()}')
    
    # encryption
    ct = xts_encdec(True, key1, key2, tweak, plaint_text, enc_func=aes128_ecb_enc, dec_func=aes128_ecb_dec)
    print(f'AES-XTS Encryption: {ct.hex()}')
    if ct.hex() == golden_cipher_text:
        print("Encryption PASS")
    else:
        print("Encryption FAIL")
    
    # decryption
    pt = xts_encdec(False, key1, key2, tweak, bytes.fromhex(golden_cipher_text), enc_func=aes128_ecb_enc, dec_func=aes128_ecb_dec)
    print(f'AES-XTS Decryption: {pt.hex()}')
    if pt.hex() == plaint_text.hex():
        print("Decryption PASS")
    else:
        print("Decryption FAIL")


def test_sm4_xts():
    # Note: for bytes, [0] is the least significant byte (lsb) and it is printed out at leftmost of a string
    key1 = os.urandom(16)
    key2 = os.urandom(16)
    tweak = os.urandom(16)
    plaint_text = os.urandom(16)
    
    # Test vector
    key1 = hex2bytes('00000000000000000000000000000000')
    key2 = hex2bytes('00000000000000000000000000000000')
    tweak = int('0', 16)
    plaint_text = bytes.fromhex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    golden_cipher_text = 'd9b421f731c894fdc35b77291fe4e3b02a1fb76698d59f0e51376c4ada5bc75d81a9e557929d5bd7a2ce1e1ea7f0e89b0b3159afe246943864a68710efa996ad'
    
    print(f'plaint_text={plaint_text.hex()}')
    
    # encryption
    ct = xts_encdec(True, key1, key2, tweak, plaint_text, enc_func=sm4_ecb_enc, dec_func=sm4_ecb_dec)
    print(f'SM4-XTS Encryption: {ct.hex()}')
    if ct.hex() == golden_cipher_text:
        print("Encryption PASS")
    else:
        print("Encryption FAIL")
    
    # decryption
    pt = xts_encdec(False, key1, key2, tweak, bytes.fromhex(golden_cipher_text), enc_func=sm4_ecb_enc, dec_func=sm4_ecb_dec)
    print(f'SM4-XTS Decryption: {pt.hex()}')
    if pt.hex() == plaint_text.hex():
        print("Decryption PASS")
    else:
        print("Decryption FAIL")

if __name__ == '__main__':

    #test_aes128_xts()
    test_sm4_xts()


