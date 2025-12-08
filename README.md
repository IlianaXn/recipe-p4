# Implementing and Evaluating RECIPE-D Using P4

This project implements RECIPE-D, a distributed LT coding algorithm for path tracing, using P4 on Barefoot Tofino switches.

## Overview

This implementation includes two approaches based on how the hash of a packet along with the hop count is computed:

- **tofino**: Uses CRC32 hash provided natively by Tofino
- **tofino_fixed_hash**: Uses precomputed uniform random hashes installed by the controller on the switch's table

## Note

For experiments, the switch ID is derived from the hop count, but the code can be easily modified to load switch ID from a register for unique identification per switch.

## Directory Structure

```
recipe-p4/
├── tofino/              # Tofino implementation with CRC32
├── tofino_fixed_hash/   # Tofino implementation with precomputed hashes
├── host/                # Host-side scripts
└── README.md
```

## Getting Started

1. **Setup**: Ensure you have Barefoot SDE installed and configured

2. **Compile**: Compile the P4 program using your SDE
    ```
    # inside the SDE root directory
    ../tools/p4_build.sh -p ../recipe-p4/tofino/recipe.p4
    ```

3. **Run**: Deploy the compiled program on a Tofino switch or Tofino model:
    ```
    # for Tofino model on a VM
    # inside SDE root directory
    # terminal 1
    ./run_tofino_model.sh -p recipe
    # terminal 2
    ./run_switchd.sh -p recipe
    ```

4. **Controller**: Run the controller script to install APA and hash values onto the switch
    ```
    # inside tofino/ or tofino_fixed_hash/ directory
    python3 controller.py --probs_path ../APA/robust64_1.txt --num_hops 64
    
    # for tofino_fixed_hash only, also provide hash values:
    python3 controller.py --probs_path ../APA/robust64_1.txt --num_hops 64 --hash_path ../recipe_hash.csv
    ```

5. **Host**: Compile and run the host sender and receiver scripts
    ```
    # inside host/ directory
    # compile
    sudo make all
    
    # terminal 1 - start receiver first
    sudo ./bin/host_receive
    
    # terminal 2 - send packets
    sudo ./bin/host_send
    ```
    
    Configure the experiment by modifying `NUM_PACKETS` and `MAX_ITER` in `host_send.cpp` and `host_receive.cpp`

## Requirements

- Barefoot SDE (version 9.13.4+)
- Python 3.6+ (for controller scripts)
- C++ compiler with C++11 support (for host scripts)