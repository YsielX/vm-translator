import json
from keystone import *
from enum import Enum


class types(Enum):
    NOP, LOAD, STORE, ADD, SUB, MUL, DIV, SHL, SHR, AND, OR, XOR, NOT, CMP, PUSH, POP, JLE, JZ, JMP, CALL, SUCCESS, FAIL, RET = [
        i for i in range(23)
    ]


class Ts(Enum):
    ARITH, STACK_ARITH, J, END = [i for i in range(4)]


ks = Ks(KS_ARCH_X86, KS_MODE_64)


class Translator():

    OpTable = {
        types.ADD: "add",
        types.SUB: "sub",
        types.MUL: "imul",
        types.DIV: "div",
        types.SHL: "shl",
        types.SHR: "shr",
        types.AND: "and",
        types.OR: "or",
        types.XOR: "xor",
        types.NOT: "not",
        types.CMP: "cmp",
        types.JMP: "jmp",
        types.JZ: "jz",
        types.JLE: "jle",
        types.CALL: "call"
    }

    def __init__(self, regnum, endian, opcodes) -> None:
        self.JumpTable = {}
        self.endian = endian
        self.opcodes = opcodes
        self.r = [f'r{i+8}' for i in range(regnum)]

    def process_NOP(self):
        encoding, _ = ks.asm(f'nop')
        return bytes(encoding), len(encoding)

    def process_LOAD(self, code: bytes, numtype: str):
        imm = int.from_bytes(code[2:], self.endian)
        if numtype == "R":
            encoding, _ = ks.asm(f'mov {self.r[code[1]]}, [{self.r[code[1]]}]')
            return bytes(encoding), len(encoding)
        if numtype == "RR":
            encoding, _ = ks.asm(f'mov {self.r[code[1]]}, [{self.r[code[2]]}]')
            return bytes(encoding), len(encoding)
        elif numtype == "RI64":
            suffix = ''
        elif numtype == "RI32":
            suffix = 'd'
        elif numtype == "RI16":
            suffix = 'w'
        elif numtype == "RI8":
            suffix = 'b'
        encoding, _ = ks.asm(
            f'mov rax, {imm};mov {self.r[code[1]]}{suffix}, [rax]')
        return bytes(encoding), len(encoding)

    def process_STORE(self, code: bytes, numtype: str):
        imm = int.from_bytes(code[2:], self.endian)
        if numtype == "R":
            encoding, _ = ks.asm(f'mov [{self.r[code[1]]}], {self.r[code[1]]}')
            return bytes(encoding), len(encoding)
        if numtype == "RR":
            encoding, _ = ks.asm(f'mov [{self.r[code[2]]}], {self.r[code[1]]}')
            return bytes(encoding), len(encoding)
        elif numtype == "RI64":
            suffix = ''
        elif numtype == "RI32":
            suffix = 'd'
        elif numtype == "RI16":
            suffix = 'w'
        elif numtype == "RI8":
            suffix = 'b'
        encoding, _ = ks.asm(
            f'mov rax, {imm};mov [rax], {self.r[code[1]]}{suffix}')
        return bytes(encoding), len(encoding)

    def process_ARITH(self, code: bytes, type: types, numtype: str):
        imm = int.from_bytes(code[2:], self.endian)
        arith = self.OpTable[type]
        if numtype == "R":
            encoding, _ = ks.asm(f'{arith} {self.r[code[1]]}')
        elif numtype == "RR":
            if type == types.SHR or type == types.SHL:
                encoding, _ = ks.asm(
                    f'mov cl, {self.r[code[2]]};{arith} {self.r[code[1]]}, cl')
                return bytes(encoding), len(encoding)
            else:
                encoding, _ = ks.asm(
                    f'{arith} {self.r[code[1]]}, {self.r[code[2]]}')
                return bytes(encoding), len(encoding)
        elif numtype == "RI64":
            suffix = ''
        elif numtype == "RI32":
            suffix = 'd'
        elif numtype == "RI16":
            suffix = 'w'
        elif numtype == "RI8":
            suffix = 'b'
        encoding, _ = ks.asm(f'{arith} {self.r[code[1]]}{suffix}, {imm}')
        return bytes(encoding), len(encoding)

    def process_STACK_ARITH(self, type: types):
        arith = self.OpTable[type]
        if type == types.SHR or type == types.SHL:
            encoding, _ = ks.asm(f'pop rax;pop rcx;{arith} rax, cl;push rax;')
        elif type == types.NOT:
            encoding, _ = ks.asm(f'pop rax;{arith} rax;push rax;')
        else:
            encoding, _ = ks.asm(f'pop rax;pop rbx;{arith} rax, rbx;push rax;')
        return bytes(encoding), len(encoding)

    def process_PUSH(self, code: bytes, numtype: str):
        if numtype == "RR":
            encoding, _ = ks.asm(f'push {self.r[code[1]]}')
            return bytes(encoding), len(encoding)
        else:
            imm = int.from_bytes(code[1:], self.endian)
            encoding, _ = ks.asm(f'mov rax, {imm};push rax')
            return bytes(encoding), len(encoding)

    def process_POP(self, code: bytes):
        encoding, _ = ks.asm(f'pop {self.r[code[1]]}')
        return bytes(encoding), len(encoding)

    def process_J(self, code: bytes, type: types, numtype: str, addr):  # jump to obsolute address
        instr = self.OpTable[type]
        if numtype == "R":
            if type == types.JMP:
                encoding, _ = ks.asm(f'{instr} {self.r[code[1]]}')
                return bytes(encoding), len(encoding)
            else:     # Conditional jump register
                pass  # not implemented
        else:
            imm = int.from_bytes(code[1:], self.endian)
            self.JumpTable[addr] = imm
            return b'', 6

    def process_CALL(self, code: bytes, numtype: str, addr):
        if numtype == "R":
            encoding, _ = ks.asm(f'call {self.r[code[1]]}')
            return bytes(encoding), len(encoding)
        else:
            imm = int.from_bytes(code[1:], self.endian)
            self.JumpTable[addr] = imm
            return b'', 5

    def process_END(self, type: types):
        match type:
            case types.SUCCESS:
                encoding, _ = ks.asm(f'mov rax, 0; ret;')
            case types.FAIL:
                encoding, _ = ks.asm(f'mov rax, 1; ret;')
            case types.RET:
                encoding, _ = ks.asm(f'ret;')
        return bytes(encoding), len(encoding)

    def fill_JumpTable(self):
        for i in self.JumpTable:
            try:
                instr = self.OpTable[self.opcodes[i][0].type]
                encoding, _ = ks.asm(
                    f'{instr} {self.opcodes[self.JumpTable[i]][1]-self.opcodes[i][1]}')
            except:
                print("jump to invalid address!")
                print(f"{i}: jump to {self.JumpTable[i]}")
                encoding = b''
            self.opcodes[i][2] = bytes(encoding).ljust(6, b'\x90')


class InstructionType():

    LengthTable = {
        "": 1,
        "R": 2,
        "RR": 3,
        "I8": 2,
        "I16": 3,
        "I32": 5,
        "I64": 9,
        "RI8": 3,
        "RI16": 4,
        "RI32": 6,
        "RI64": 10
    }

    def __init__(self, type, numtype, T=None) -> None:
        self.type = type
        self.numtype = numtype
        self.T = T
        self.len = self.LengthTable[numtype]


class Instruction(InstructionType):

    def __init__(self, instrtype: InstructionType, code, addr, translator: Translator) -> None:
        super().__init__(instrtype.type, instrtype.numtype, instrtype.T)
        self.code = code
        self.addr = addr
        self.translator = translator

    def process(self):
        if self.T:
            match self.T:
                case Ts.ARITH:
                    return self.translator.process_ARITH(self.code, self.type, self.numtype)
                case Ts.STACK_ARITH:
                    return self.translator.process_STACK_ARITH(self.type)
                case Ts.J:
                    return self.translator.process_J(self.code, self.type, self.numtype, self.addr)
                case Ts.END:
                    return self.translator.process_END(self.type)
        else:
            match self.type:
                case types.NOP:
                    return self.translator.process_NOP()
                case types.LOAD:
                    return self.translator.process_LOAD(self.code, self.numtype)
                case types.STORE:
                    return self.translator.process_STORE(self.code, self.numtype)
                case types.PUSH:
                    return self.translator.process_PUSH(self.code, self.numtype)
                case types.POP:
                    return self.translator.process_POP(self.code)
                case types.CALL:
                    return self.translator.process_J(self.code, self.numtype, self.addr)


class GeneralVM():

    properties = {
        "nop" : InstructionType(types.NOP, ""),

        "ldimm64": InstructionType(types.LOAD, "RI64"),
        "ldimm32": InstructionType(types.LOAD, "RI32"),
        "ldimm16": InstructionType(types.LOAD, "RI16"),
        "ldimm8": InstructionType(types.LOAD, "RI8"),
        "ldreg": InstructionType(types.LOAD, "RR"),
        "ldfast" : InstructionType(types.LOAD, "R"),   # ld Rx, [Rx]

        "stimm64": InstructionType(types.STORE, "RI64"),
        "stimm32": InstructionType(types.STORE, "RI32"),
        "stimm16": InstructionType(types.STORE, "RI16"),
        "stimm8": InstructionType(types.STORE, "RI8"),
        "streg": InstructionType(types.STORE, "RR"),
        "stfast" : InstructionType(types.STORE, "R"),   # st Rx, [Rx]

        "addimm64": InstructionType(types.ADD, "RI64", Ts.ARITH),
        "addimm32": InstructionType(types.ADD, "RI32", Ts.ARITH),
        "addimm16": InstructionType(types.ADD, "RI16", Ts.ARITH),
        "addimm8": InstructionType(types.ADD, "RI8", Ts.ARITH),
        "addreg": InstructionType(types.ADD, "RR", Ts.ARITH),

        "subimm64": InstructionType(types.SUB, "RI64", Ts.ARITH),
        "subimm32": InstructionType(types.SUB, "RI32", Ts.ARITH),
        "subimm16": InstructionType(types.SUB, "RI16", Ts.ARITH),
        "subimm8": InstructionType(types.SUB, "RI8", Ts.ARITH),
        "subreg": InstructionType(types.SUB, "RR", Ts.ARITH),

        "mulimm64": InstructionType(types.MUL, "RI64", Ts.ARITH),
        "mulimm32": InstructionType(types.MUL, "RI32", Ts.ARITH),
        "mulimm16": InstructionType(types.MUL, "RI16", Ts.ARITH),
        "mulimm8": InstructionType(types.MUL, "RI8", Ts.ARITH),
        "mulreg": InstructionType(types.MUL, "RR", Ts.ARITH),

        "divimm64": InstructionType(types.DIV, "RI64", Ts.ARITH),
        "divimm32": InstructionType(types.DIV, "RI32", Ts.ARITH),
        "divimm16": InstructionType(types.DIV, "RI16", Ts.ARITH),
        "divimm8": InstructionType(types.DIV, "RI8", Ts.ARITH),
        "divreg": InstructionType(types.DIV, "RR", Ts.ARITH),

        "shlimm64": InstructionType(types.SHL, "RI64", Ts.ARITH),
        "shlimm32": InstructionType(types.SHL, "RI32", Ts.ARITH),
        "shlimm16": InstructionType(types.SHL, "RI16", Ts.ARITH),
        "shlimm8": InstructionType(types.SHL, "RI8", Ts.ARITH),
        "shlreg": InstructionType(types.SHL, "RR", Ts.ARITH),

        "shrimm64": InstructionType(types.SHR, "RI64", Ts.ARITH),
        "shrimm32": InstructionType(types.SHR, "RI32", Ts.ARITH),
        "shrimm16": InstructionType(types.SHR, "RI16", Ts.ARITH),
        "shrimm8": InstructionType(types.SHR, "RI8", Ts.ARITH),
        "shrreg": InstructionType(types.SHR, "RR", Ts.ARITH),

        "andimm64": InstructionType(types.AND, "RI64", Ts.ARITH),
        "andimm32": InstructionType(types.AND, "RI32", Ts.ARITH),
        "andimm16": InstructionType(types.AND, "RI16", Ts.ARITH),
        "andimm8": InstructionType(types.AND, "RI8", Ts.ARITH),
        "andreg": InstructionType(types.AND, "RR", Ts.ARITH),

        "orimm64": InstructionType(types.OR, "RI64", Ts.ARITH),
        "orimm32": InstructionType(types.OR, "RI32", Ts.ARITH),
        "orimm16": InstructionType(types.OR, "RI16", Ts.ARITH),
        "orimm8": InstructionType(types.OR, "RI8", Ts.ARITH),
        "orreg": InstructionType(types.OR, "RR", Ts.ARITH),

        "xorimm64": InstructionType(types.XOR, "RI64", Ts.ARITH),
        "xorimm32": InstructionType(types.XOR, "RI32", Ts.ARITH),
        "xorimm16": InstructionType(types.XOR, "RI16", Ts.ARITH),
        "xorimm8": InstructionType(types.XOR, "RI8", Ts.ARITH),
        "xorreg": InstructionType(types.XOR, "RR", Ts.ARITH),

        "notreg": InstructionType(types.NOT, "R", Ts.ARITH),

        "stackadd": InstructionType(types.ADD, "", Ts.STACK_ARITH),
        "stacksub": InstructionType(types.SUB, "", Ts.STACK_ARITH),
        "stackmul": InstructionType(types.MUL, "", Ts.STACK_ARITH),
        "stackdiv": InstructionType(types.DIV, "", Ts.STACK_ARITH),
        "stackshl": InstructionType(types.SHL, "", Ts.STACK_ARITH),
        "stackshr": InstructionType(types.SHR, "", Ts.STACK_ARITH),
        "stackand": InstructionType(types.AND, "", Ts.STACK_ARITH),
        "stackor": InstructionType(types.OR, "", Ts.STACK_ARITH),
        "stackxor": InstructionType(types.XOR, "", Ts.STACK_ARITH),
        "stacknot": InstructionType(types.NOT, "", Ts.STACK_ARITH),
        "stackcmp": InstructionType(types.CMP, "", Ts.STACK_ARITH),

        "pushimm64": InstructionType(types.PUSH, "I64"),
        "pushimm32": InstructionType(types.PUSH, "I32"),
        "pushimm16": InstructionType(types.PUSH, "I16"),
        "pushimm8": InstructionType(types.PUSH, "I8"),
        "pushreg": InstructionType(types.PUSH, "R"),

        "popreg": InstructionType(types.POP, "R"),

        "jleimm64": InstructionType(types.JLE, "I64", Ts.J),
        "jleimm32": InstructionType(types.JLE, "I32", Ts.J),
        "jleimm16": InstructionType(types.JLE, "I16", Ts.J),
        "jleimm8": InstructionType(types.JLE, "I8", Ts.J),

        "jzimm64": InstructionType(types.JZ, "I64", Ts.J),
        "jzimm32": InstructionType(types.JZ, "I32", Ts.J),
        "jzimm16": InstructionType(types.JZ, "I16", Ts.J),
        "jzimm8": InstructionType(types.JZ, "I8", Ts.J),

        "jmpimm64": InstructionType(types.JMP, "I64", Ts.J),
        "jmpimm32": InstructionType(types.JMP, "I32", Ts.J),
        "jmpimm16": InstructionType(types.JMP, "I16", Ts.J),
        "jmpimm8": InstructionType(types.JMP, "I8", Ts.J),
        "jmpreg": InstructionType(types.JMP, "R", Ts.J),

        "callimm64": InstructionType(types.CALL, "I64"),
        "callimm32": InstructionType(types.CALL, "I32"),
        "callimm16": InstructionType(types.CALL, "I16"),
        "callimm8": InstructionType(types.CALL, "I8"),
        "callreg": InstructionType(types.CALL, "R"),

        "success": InstructionType(types.SUCCESS, "", Ts.END),
        "fail": InstructionType(types.FAIL, "", Ts.END),
        "ret": InstructionType(types.RET, "", Ts.END),

    }

    def __init__(self, configfile: str) -> None:
        with open(configfile, 'r') as fd:
            config = json.loads(fd.read())
            fd.close()
        self.RISC = config["RISC"]
        self.endian = config["endian"]
        self.reg_num = config["num_of_regs"]
        self.rule: dict = config["ops"]

    def preprocess(self, codes: bytes):
        current_vmaddr = 0
        while current_vmaddr < len(codes):
            opcode = str(codes[current_vmaddr])
            try:
                name = self.rule[opcode]
                instr_type = self.properties[name]
                new_instruction = Instruction(
                    instr_type, codes[current_vmaddr:current_vmaddr+instr_type.len], current_vmaddr, self.translator)
                self.opcodes[current_vmaddr] = [new_instruction]
                current_vmaddr += instr_type.len
            except:
                print(f"invalid opcode at {current_vmaddr}!")
                raise

    def analyse(self):
        if self.RISC:
            self.analyse_RISC()
        else:
            self.analyse_bytecode()

    def analyse_RISC(self):
        pass

    def analyse_bytecode(self):
        current_x86addr = 0
        for current_vmaddr in self.opcodes:
            x86_instr, size = self.opcodes[current_vmaddr][0].process()
            self.opcodes[current_vmaddr] += [current_x86addr, x86_instr]
            current_x86addr += size

    def fill_jumptable(self):
        self.translator.fill_JumpTable()

    def to_x64(self, codes: bytes) -> bytes:
        self.opcodes = {}
        self.translator = Translator(self.reg_num, self.endian, self.opcodes)
        # format: { vmaddr: [vm_instr, x86_addr, x86_instr] }
        self.preprocess(codes)
        self.analyse()
        self.fill_jumptable()

        x86_asm = b''
        for i in sorted(self.opcodes):
            x86_asm += self.opcodes[i][2]

        return x86_asm
