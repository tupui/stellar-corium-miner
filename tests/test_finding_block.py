import binascii

import stellar_sdk

import corium_miner


def test_finding_block():

    corium_miner.miner_bytes = stellar_sdk.scval.to_address("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAITA4").to_xdr_bytes()

    block_hash, nonce = corium_miner.finding_block(
        idx=95,
        message="Hi there",
        prev_hash=binascii.unhexlify("00000000d9ae75cff9ee7fc3eefccb40f06e729ccd552b90a1843179db15eb34"),
        difficulty=2,
        nonce=0
    )

    assert nonce == 352
    assert block_hash.hex() == "00d310e1902ff7d51a471b9b1bc9740be87fb8d824cec2f159875854685ef2d3"
