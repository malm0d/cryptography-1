import argparse
import math
from pathlib import Path
from cryptography.hazmat.primitives import hashes


def SHA256(blocks: list[bytes]) -> bytes:
    digest = hashes.Hash(hashes.SHA256())

    for block in blocks:
        digest.update(block)

    res: bytes = digest.finalize()
    return res

def split_to_blocks(msg: bytes) -> list[bytes]:
    block_size_bytes = 1024
    res: list[bytes] = []

    for i in range(0, len(msg), block_size_bytes):
        res.append(msg[i:i + block_size_bytes])

    assert len(res) == math.ceil(len(msg) / block_size_bytes)

    return res

def hash_file(_file: bytes) -> bytes:
    msg_blocks: list[bytes] = split_to_blocks(_file)
    last_block: bytes = msg_blocks.pop() # pop last and mutate msg_blocks
    msg_blocks.reverse()

    # h_i = H(msgblock_i || h_{i+1})
    _hash: bytes = SHA256([last_block])
    for msg_block in msg_blocks:
        _hash = SHA256([msg_block + _hash])
    
    return _hash
    

def main():
    #..../module3/input
    INPUT_DIR = Path(__file__).resolve().parent / "input"
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    args = parser.parse_args()
    path = INPUT_DIR / args.filename
    file_bytes = path.read_bytes()

    h0 = hash_file(file_bytes)
    print(h0.hex())

    # test_bytes = bytes.fromhex("03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8")
    # assert h0 == test_bytes, "hash mismatch"


if __name__ == "__main__":
    main()