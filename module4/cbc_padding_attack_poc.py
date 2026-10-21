import time
import urllib.request
import urllib.parse

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


# POC for simple case with the last two ciphertext blocks.
# Here we try to force the padding to be a single byte length pad.
def main():
    PO = PaddingOracle()
    ct_blocks = split_to_blocks(SAMPLE, 16)

    # Test for correct padding, but wrong msg from original CT.
    # Our msg is considered wrong because we only use 2 blocks (of 4).
    testcode = PO.query(ct_blocks[2].hex() + ct_blocks[3].hex())
    assert testcode == 404
    time.sleep(0.2)

    original_ct2 = bytearray(ct_blocks[2])

    for delta in range(256):
        ct_blocks[2][-1] = original_ct2[-1] ^ delta ^ 0x01
        res = PO.query(ct_blocks[2].hex() + ct_blocks[3].hex())
        
        # There might be case where delta ^ 0x01 cancels each other,
        # so we need to verify that delta is actually a true hit.
        if res != 403:

            # If delta is a true hit, then the last byte of the plaintext should
            # change to 0x01 (1 byte pad len), so corrupting the second last byte
            # of c[2] should be no conseq. to padding check since its now treated as 
            # part of the plaintext. So in both instances we should get 404.
            #
            # But if delta is false hit, then last byte of plaintext remains unchanged,
            # corrupting the second last bye of c[2] attempts to break a multi-byte pad
            # in plaintext. So we should expect the second query to reject with 403.
            ct_blocks[2][-2] ^= 0x01
            verify = PO.query(ct_blocks[2].hex() + ct_blocks[3].hex())
            ct_blocks[2][-2] = original_ct2[-2]
            print(f"delta={delta}: initial_res={res}, verify_res={verify}")
            
        time.sleep(0.2)


if __name__ == "__main__":
    main()