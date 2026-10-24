import urllib.request
import urllib.parse
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

        pad_value = BLOCKSIZE - byte_idx    #BLOCKSIZE = 16

        # If target_ct_block is the last block, then PKCS7 pad applies.
        # PKCS7 pad length range = [1, 16] bytes (16 byte long means dummy block).
        # 
        # Regarding target_ct_block (with pad or not), for the correct g:
        #
        # - At byte_idx = 15, we're looking to mutate last 1 byte of target msg block m. 
        #   The last byte of m, i.e m[15], XORs to 1, so pad of m' will be [1].
        #  
        # - At byte_idx = 14, we're looking to mutate last 2 bytes target msg block m.
        #   The 2nd last byte of m, i.e m[14], XORs to 2, but pad must be [2][2]. So prior to
        #   querying oracle, since last byte of m is already solved (we know g for m[15]), then
        #   we do prev_ct_block[15] XOR m[15] XOR 2 so that the m[15] is also XORed to 2 such
        #   that the correct PKCS7 pad [2][2] on m after decryption.
        # 
        # To prepare the prev CT block for guessing so we get correct pad format at end of the
        # PT after decrypting:
        #
        # - byte_idx = 15 points to the LSB, we get pad_value = 1. There is no solved
        #   trailing-byte (position to the right) that we need to convert to the pad.
        #
        # - For every other byte_idx, we would have solved trailing-bytes at all pos to its right. 
        #   Means for all pos to the right of byte_idx, we need to XOR with all previous correct
        #   guesses to cancel out so we can XOR the corresponding pad_value into the those positions.
        #   Byte at byte_idx remains untouched because we need to guess it.
        #   E.g. byte_idx = 10, so pad_value = 6, prev_ct_block_mut should look like the following:
        #   [... byte_idx 0 to 9 ...][byte_idx 10 untouched for guessing][6][6][6][6][6]
        #
        if byte_idx != 15:
            trail_idx = byte_idx + 1
            for i in range(trail_idx, BLOCKSIZE):
                prev_ct_block_mut[i] = prev_ct_block[i] ^ plaintext_bytes[i] ^ pad_value

        # Guess from 0 to 255 for each byte_idx.
        # m[i]' <- D(k, c[i]) XOR c[i-1] XOR g XOR pad
        for g in range(256):
            print(f"g={g}")
            prev_ct_block_mut[byte_idx] = prev_ct_block[byte_idx] ^ g ^ pad_value
            res = pad_oracle.query(prev_ct_block_mut.hex() + target_ct_block.hex())

            # Consider case where g == pad_value, this effectively cancels the delta.
            # Then the decrypted byte at byte_idx remains unchanged.
            #
            # If prev_ct_block and target_block are NOT the last 2 blocks, then there is no
            # PKCS7 padding because padding is only in last block. Querying oracle will always
            # return invalid pad (403) since g == pad_value cancels the delta. When g == byte_idx
            # then pad_value gets XORed into byte_idx and this creates valid pad for oracle.
            #
            # If prev_ct_block and target_block are the last 2 blocks, then the original PKCS7
            # padding will be fully intact, so the oracle still sees a valid pad. Thus g is a false
            # positive since g ^ pad_value cancelled out, and pad_value is not XORed into byte_idx.
            #
            # - This will only be an issue with forcing 1-byte pad (i.e pad_value = 1, byte_idx == 15).
            #   When g = 1, g ^ pad_value cancels, then entire block remains unmodified with original
            #   pad and oracle accepts. By mutating [byte_idx - 1] (index 14), which mutates the 
            #   second last byte:
            #
            #   -> If original pad is a multi-byte pad, the mutation intentionally breaks the PKCS7 pad,
            #      and oracle rejects (403) since the pad would look like: [...][3][x][3]. So g is false 
            #      hit.
            #
            #   -> If original pad is a 1-byte pad, then g = 1 is correct guess. While g ^ pad_value
            #      cancelled out, and the mutation flips the second last byte, the oracle will still 
            #      accept (404) since the pad is correct: [...][x][1]. So g = 1 is a true hit.
            #     
            # - This is not an issue for forcing multi-byte pad (i.e. pad_value != 1, byte_idx < 15). 
            #   Here, the trailing bytes to right of byte_idx have already been changed to pad_value
            #   since we already solved g for those positions. So even if g == pad_value leaves the
            #   byte at byte_idx unchanged, this would create an invalid PKCS7 pad which the oracle
            #   will reject.
            #   -> E.g. byte_idx = 13, pad_value = 3, g = 3, expected pad: [...][3][3][3].
            #      But decrypted: [....][byte_idx unchanged][3][3] -> invalid pad.
            #
            if res != 403:
                if pad_value == 1:
                    temp = prev_ct_block_mut[byte_idx - 1]
                    prev_ct_block_mut[byte_idx - 1] ^= 0x01
                    verify_hit = pad_oracle.query(prev_ct_block_mut.hex() + target_ct_block.hex())
                    prev_ct_block_mut[byte_idx -1] = temp

                    if verify_hit != 404:
                        continue
                    
                plaintext_bytes[byte_idx] = g

    return plaintext_bytes


def main():
    PO: PaddingOracle = PaddingOracle()
    ct_blocks: list[bytearray] = split_to_blocks(SAMPLE, 16)
    
    # Test for correct padding, but wrong msg from original CT
    testcode = PO.query(ct_blocks[2].hex() + ct_blocks[3].hex())
    assert testcode == 404

    pt_blocks: list[bytearray] = []

    num_blocks = len(ct_blocks)
    last_idx = num_blocks - 1
    for i in range(0, last_idx):
        target_block: bytearray = ct_blocks[last_idx - i]
        prev_block: bytearray = ct_blocks[last_idx - i - 1]

        # pt_block corresponds to target_block
        pt_block: bytearray = decrypt(prev_block, target_block, PO)

        pt_blocks.append(pt_block)
        
    pt_blocks.reverse()

    decrypted = b"".join(pt_blocks)

    unpadder = padding.PKCS7(128).unpadder()

    true_plaintext = unpadder.update(decrypted) + unpadder.finalize()

    print(true_plaintext)

if __name__ == "__main__":
    main()