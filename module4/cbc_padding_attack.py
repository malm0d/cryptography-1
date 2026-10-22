import sys
import time
import urllib.request
import urllib.parse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# CBC rand IV decryption
# m[0] <- D(k, c[0]) XOR IV
# m[1] <- D(k, c[1]) XOR c[0]
# m[1]' <- m[1] XOR (g XOR pad), if g is correct.

TARGET = 'http://crypto-class.appspot.com/po?er='
SAMPLE = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4"

BLOCKSIZE = 16 # bytes (AES)

# 404 means valid padding, but malformed msg.
# 403 means padding invalid.
class PaddingOracle(object):
    def query(self, q):
        target_url = TARGET + urllib.parse.quote(q)
        req = urllib.request.Request(target_url)
        try:
            res = urllib.request.urlopen(req)
            return res.code
        except urllib.error.HTTPError as e:
            return e.code

# Use bytearray for mutability
def split_to_blocks(ct: str, blocksizebytes: int) -> list[bytearray]:
    ct_bytes: bytes = bytes.fromhex(ct)
    res: list[bytearray] = []
    for i in range(0, len(ct_bytes), blocksizebytes):
        res.append(bytearray(ct_bytes[i : i + blocksizebytes]))
    return res


def decrypt(
        prev_ct_block: bytearray,
        target_ct_block: bytearray,
        pad_oracle: PaddingOracle
) -> bytearray:
    # Lengths of block inputs must both be 16 bytes
    assert len(prev_ct_block) == len(target_ct_block) == BLOCKSIZE

    # 16 bytes of zeroes
    plaintext_bytes: bytearray = bytearray(BLOCKSIZE)

    # Clone of prev_ct_block which we mutate
    prev_ct_block_mut = bytearray(prev_ct_block)

    # Start from LSB of prev_ct_block, so prev_ct_block[i] : i = 15, ..., 0
    for byte_idx in range(15, -1, -1):

        # PKCS7 pad length range = [1, 16] bytes (16 byte long means dummy block).
        # For the correct g:
        # - If byte_idx = 15, we're looking to mutate last 1 byte of m[i]'. 
        #   The last byte of m[i]' XORs to 1, so pad will be [1].
        # - If byte_idx = 14, we're looking to mutate last 2 bytes of m[i]'.
        #   The 2nd last byte of m[i]' XORs to 2, but pad must be [2,2], so need to
        #   take the correct g of byte_idx = 15, then c[i-1][15] XOR g_15 XOR 2.

        pad_value = BLOCKSIZE - byte_idx    #BLOCKSIZE = 16

        # At byte_idx = 15 points to the LSB, where pad_value = 1, There is no solved
        # trailing-bytes (positions to the right) that we need to convert to the pad of pad_value.
        # Every other byte_idx would have solved trailing-byte(s) at all pos to the right, 
        # which means for all pos to the right, we XOR prev_ct_block_mut with correct guess, 
        # and XOR again with pad_value construct the correct pad to the right of the byte that
        # needs to be guessed.
        if byte_idx != 15:
            for i in range(byte_idx, BLOCKSIZE):



        # Guess from 0 to 255 for each byte_idx
        # m[i]' <- D(k, c[i]) XOR c[i-1] XOR g XOR pad, if g correct, last byte = pad
        for g in range(256):
            prev_ct_block_mut[byte_idx] = prev_ct_block[byte_idx] ^ g ^ pad
            res = pad_oracle.query(prev_ct_block_mut.hex() + target_ct_block.hex())
            
            if res != 403:
                plaintext_bytes[byte_idx] = g

    


def main():
    PO = PaddingOracle()
    ct_blocks = split_to_blocks(SAMPLE, 16)

    IV = ct_blocks[0]
    
    # Test for correct padding, but wrong msg from original CT
    testcode = PO.query(ct_blocks[2].hex() + ct_blocks[3].hex())
    assert testcode == 404


if __name__ == "__main__":
    main()