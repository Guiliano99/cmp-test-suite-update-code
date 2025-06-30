# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Script to generate XMSS private keys used for tests."""

import argparse
import os
import re

from pq_logic.combined_factory import CombinedKeyFactory
from resources.keyutils import generate_key, save_key

ALL_REQUEST_BODY_NAMES = [
    "ir",
    "cr",
    "kur",
    "p10cr",
    "ccr",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-kur",
    "added-protection-inner-p10cr",
    "added-protection-inner-ccr",
    "batch-inner-ir",
    "batch-inner-cr",
    "batch-inner-kur",
    "batch-inner-p10cr",
    "batch-inner-ccr",
]

parser = argparse.ArgumentParser(description="Generate XMSS private keys")
parser.add_argument(
    "--batch",
    type=int,
    default=1,
    help="Batch number to generate (1 based)",
)
parser.add_argument(
    "--num-batches",
    type=int,
    default=5,
    help="Total number of batches",
)
args = parser.parse_args()

print("Generating XMSS keys (batch %d/%d)..." % (args.batch, args.num_batches))
print("This may take a while, please be patient...")
print("All keys will be saved in the `data/keys/xmss_xmssmt_key_verbose` directory.")
if not os.path.exists("data/keys/xmss_xmssmt_key_verbose"):
    os.makedirs("data/keys/xmss_xmssmt_key_verbose", exist_ok=True)

all_algs = CombinedKeyFactory.get_stateful_sig_algorithms()["xmss"]
all_algs.sort()


def _height_from_name(name: str) -> int:
    match = re.search(r"_(\d+)_", name)
    return int(match.group(1)) if match else 10


def _select_algorithms(algs, num_batches, batch_num):
    weighted = sorted(algs, key=_height_from_name, reverse=True)
    batches = [[] for _ in range(num_batches)]
    weights = [0] * num_batches
    for alg in weighted:
        idx = weights.index(min(weights))
        batches[idx].append(alg)
        weights[idx] += _height_from_name(alg)
    return batches[batch_num - 1]


selected_algs = _select_algorithms(all_algs, args.num_batches, args.batch)
print("All available algorithms:", all_algs)
print("Algorithms selected for this batch:", selected_algs)
import oqs
print("Available STFL algorithms:", oqs.get_enabled_stateful_sig_mechanisms())

for body_name in ALL_REQUEST_BODY_NAMES:
    for alg in selected_algs:
        for reason in ["bad_pop", "popo", "bad_params", "bad_key_size", "exhausted"]:
            dir_name = "data/keys/xmss_xmssmt_key_verbose"
            path = os.path.join(dir_name, f"{alg.lower()}_{body_name}_{reason}.pem")
            if os.path.exists(path):
                continue

            key = generate_key(alg.lower())
            save_key(key, path)

            print("Finished Key: ", f"{alg.lower()}_{body_name}_{reason}")

        print("Finished algorithm", alg.lower(), "for body name", body_name)