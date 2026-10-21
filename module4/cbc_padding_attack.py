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
#
# We are given that first ciphertext block is IV.

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


def main():
    PO = PaddingOracle()
    ct_blocks = split_to_blocks(SAMPLE, 16)

    # Test for correct padding, but wrong msg from original CT
    testcode = PO.query(ct_blocks[2].hex() + ct_blocks[3].hex())
    assert testcode == 404


if __name__ == "__main__":
    main()