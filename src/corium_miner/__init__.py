import binascii
import random
import time

import stellar_sdk
from stellar_sdk import xdr, scval

import soroban

from corium_miner import rs_corium_digger  # noqa


CONTRACT_ID = "CC5TSJ3E26YUYGYQKOBNJQLPX4XMUHUY7Q26JX53CJ2YUIZB5HVXXRV6"

identity = soroban.Identity()
network = soroban.NetworkConfig()
soroban_server = stellar_sdk.SorobanServer(network.rpc_url)

miner = identity.public_key
stellar_sdk.scval.to_address(miner).to_xdr_bytes()
miner_bytes = stellar_sdk.scval.to_address(miner).to_xdr_bytes()
nonce_xdr_const = b'\x00\x00\x00\x05'


def _get_ledger_key_scval(contract_id: str, symbol_text: scval) -> scval:
    ledger_key = xdr.LedgerKey(
        type=xdr.LedgerEntryType.CONTRACT_DATA,
        contract_data=xdr.LedgerKeyContractData(
            contract=stellar_sdk.Address(contract_id).to_xdr_sc_address(),
            key=symbol_text,
            durability=xdr.ContractDataDurability.PERSISTENT,
        ),
    )
    return ledger_key


def current_block() -> tuple[int, int, bytes]:
    keys = _get_ledger_key_scval(CONTRACT_ID, xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE))

    data = soroban_server.get_ledger_entries([keys])
    xdr_res = data.entries[0].xdr
    ledger_data = xdr.LedgerEntryData.from_xdr(xdr_res)
    contract_data = ledger_data.contract_data.val.instance.storage.sc_map[
        0
    ].val.map.sc_map
    idx, difficulty = (
        scval.to_native(contract_data[0].val),
        scval.to_native(contract_data[1].val),
    )

    args = [
        {
            "name": "value",
            "type": "vec",
            "value": [
                {"type": "symbol", "value": "Block"},
                {"type": "uint64", "value": idx},
            ],
        },
    ]
    args = soroban.Parameters(args=args)
    keys = args.args[0].value
    keys = _get_ledger_key_scval(CONTRACT_ID, keys)

    data = soroban_server.get_ledger_entries([keys])
    xdr_res = data.entries[0].xdr
    ledger_data = xdr.LedgerEntryData.from_xdr(xdr_res)
    contract_data = ledger_data.contract_data.val.map.sc_map
    prev_hash = scval.to_native(contract_data[0].val)

    return idx, difficulty, prev_hash


def finding_block(
    idx: int, message: str, prev_hash: bytes, difficulty: int, nonce: int
) -> tuple[bool, bytes | None, int]:

    idx_message_prev_hash_nonce_xdr_const_ = (
        stellar_sdk.scval.to_uint64(idx).to_xdr_bytes()
        + stellar_sdk.scval.to_string(message).to_xdr_bytes()
        + stellar_sdk.scval.to_bytes(prev_hash).to_xdr_bytes()
        + nonce_xdr_const
    )

    success, block_hash, nonce = rs_corium_digger.dig(idx_message_prev_hash_nonce_xdr_const_, miner_bytes, nonce, difficulty)

    block_hash = bytes(bytearray(block_hash))

    return success, block_hash, nonce


def mine(message: str):
    idx, difficulty, prev_hash = current_block()
    itime = time.monotonic()
    nonce = 0

    success, block_hash, nonce = finding_block(
        idx=idx+1,
        message=message,
        prev_hash=prev_hash,
        difficulty=difficulty,
        nonce=nonce,
    )

    iter_time = time.monotonic() - itime

    print(f"Digging block: {idx+1} | difficulty: {difficulty} | {nonce / (iter_time * 1e6)} Mega Hash/s | nonce: {nonce}")  # | last hash - {binascii.b2a_hex(prev_hash)}")

    if not success:
        return -1

    args = [
        {"name": "hash", "type": "bytes", "value": block_hash},
        {"name": "message", "type": "string", "value": message},
        {"name": "nonce", "type": "uint64", "value": nonce},
        {"name": "miner", "type": "address", "value": miner},
    ]
    args = soroban.Parameters(args=args)

    try:
        soroban.invoke(
            contract_id=CONTRACT_ID,
            function_name="mine",
            args=args,
            source_account=identity,
            network=network,
        )
    except Exception as exc:
        print(f"\n\nDamn it, the shaft collapsed!\n\n{exc}\n\n")
        return -1
    else:
        print(f"\n\nWe found a block! {idx+1} : {nonce} : {binascii.b2a_hex(block_hash)}\n\n")

    return idx


# Let's go!

def main():
    mined_idx = -1

    while "And we diggy diggy hole...":
        idx, *_ = current_block()
        if mined_idx == idx:
            time.sleep(1)
            mined_idx = idx
            continue

        restart_nonce = random.randint(0, 100)
        message = f"TANSU{restart_nonce}"

        print(f"\n\nAnd we diggy diggy hole... {message}\n\n")

        mined_idx = mine(message=message)


if __name__ == "__main__":
    main()
