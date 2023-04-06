# vm-translator

**Translate virtual machine code into x86_64 assembly instructions for IDA to decompile, analyze and debug**
Currently, bytecode instruction translation is implemented (less than eight registers)

Usage:
`python vm_translator.py --instr_set VM.json --bin binarycode`
It will generate a binary file for *x86_64* architecture.

The basic format can be viewed in `non-RISC.json`.

> TODO:
> RISC Analysis
> More registers
> Refactoring for Object-oriented
> Optimization

