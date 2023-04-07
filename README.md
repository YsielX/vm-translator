# vm-translator

**Translate virtual machine code into x86_64 assembly instructions for IDA to decompile, analyze and debug in reverse engineering.**

Currently, bytecode instruction translation is implemented (less than eight registers)

### Usage:

`python run.py --config VM.json --bin binarycode`

It will generate a binary file for *x86_64* architecture.

The basic format can be viewed in `non-RISC.json`.

### TODO:
1. RISC Analysis
2. More registers
3. ~~Refactoring for Object-oriented~~
4. Instruction Optimization

