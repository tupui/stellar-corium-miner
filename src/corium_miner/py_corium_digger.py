import binascii
import random
import time

import stellar_sdk
from stellar_sdk import xdr, scval
from Crypto.Hash import keccak


nonce_xdr_const = b'\x00\x00\x00\x05'


def finding_block(
    idx: int, message: str, prev_hash: bytes, miner: str, difficulty: int, nonce: int
) -> tuple[bytes | None, int]:
    curr_difficulty = -1
    idx_message_prev_hash_nonce_xdr_const_ = (
        stellar_sdk.scval.to_uint64(idx).to_xdr_bytes()
        + stellar_sdk.scval.to_string(message).to_xdr_bytes()
        + stellar_sdk.scval.to_bytes(prev_hash).to_xdr_bytes()
        + nonce_xdr_const
    )
    miner_ = stellar_sdk.scval.to_address(miner).to_xdr_bytes()
    block_hash = None

    while curr_difficulty != difficulty:
        nonce += 1

        if nonce % 5_000_000 == 0:
            return None, nonce

        data_hash = (
            idx_message_prev_hash_nonce_xdr_const_
            + nonce.to_bytes(length=8, byteorder='big')
            + miner_
        )

        # 256 // 8 = 32
        block_hash = keccak.Keccak_Hash(data=data_hash, digest_bytes=32, update_after_digest=False).digest()

        hex_ = block_hash.hex()
        curr_difficulty = len(hex_) - len(hex_.lstrip("0"))

    return block_hash, nonce
