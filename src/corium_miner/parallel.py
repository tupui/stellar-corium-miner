import binascii
import itertools
import multiprocessing as mp
from queue import Empty
import time

import soroban

import corium_miner


N_WORKERS = 5
CONTRACT_ID = "CC5TSJ3E26YUYGYQKOBNJQLPX4XMUHUY7Q26JX53CJ2YUIZB5HVXXRV6"


identity = soroban.Identity()
network = soroban.NetworkConfig()
miner = identity.public_key


def worker(input, output):
    for args in iter(input.get, 'STOP'):
        result = corium_miner.finding_block(**args)
        output.put((args["message"], result))


def main():

    messages = itertools.cycle([f"TANSU_{i}" for i in range(N_WORKERS)])

    # get block
    idx, difficulty, prev_hash = corium_miner.current_block()

    task_queue = mp.Queue()
    done_queue = mp.Queue()

    def fire_processes(idx, prev_hash, difficulty):
        for _ in range(N_WORKERS):
            task_queue.put(
                dict(
                    idx=idx+1,
                    message=next(messages),
                    prev_hash=prev_hash,
                    difficulty=difficulty,
                    nonce=0,
                )
            )

        # Start worker processes
        processes = []
        for _ in range(N_WORKERS):
            process = mp.Process(target=worker, args=(task_queue, done_queue))
            process.start()
            processes.append(process)
        return processes

    processes = fire_processes(idx, prev_hash, difficulty)

    while "And we diggy diggy hole...":
        itime = time.monotonic()
        while "Crushing hashes":
            idx, difficulty, curr_hash = corium_miner.current_block()
            if curr_hash != prev_hash:
                task_queue.empty()
                done_queue.empty()
                for process in processes:
                    process.terminate()
                processes = fire_processes(idx, curr_hash, difficulty)

            prev_hash = curr_hash

            try:
                message, [success, block_hash, nonce] = done_queue.get(timeout=3)
                iter_time = time.monotonic() - itime
                print(f"Digging block: {idx+1} | difficulty: {difficulty} | {(nonce / 1e6) / iter_time} Mega Hash/s | nonce: {nonce}")
                itime = time.monotonic()
                if success:
                    break
            except Empty:
                print(f"Digging block: {idx+1} | difficulty: {difficulty}")
                continue

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
        else:
            print(f"\n\nWe found a block! {idx+1} : {nonce} : {binascii.b2a_hex(block_hash)}\n\n")


if __name__ == "__main__":
    main()
