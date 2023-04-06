from keystone import *
import argparse
import json

trans_code={} # format: { vmaddr: [x86addr, x86instrs] }
parser = argparse.ArgumentParser()
parser.add_argument('--instr_set')
parser.add_argument('--bin')
args = parser.parse_args()
instr_set=json.loads(open(args.instr_set,"r").read())
code=open(args.bin,'rb').read()
ks=Ks(KS_ARCH_X86,KS_MODE_64)

if instr_set["RISC"]==False:

    ops:dict=instr_set["ops"]
    endian=instr_set["endian"]
    word_len=instr_set["word_len"]
    current_vmaddr=0
    current_x86addr=0

    if instr_set["num_of_regs"]<=8:
        r=[f'r{i+8}' for i in range(instr_set["num_of_regs"])]
        jumptable,calltable={},{}

        def process_ld(offset,bytelen):
            imm=int.from_bytes(code[2+offset:2+offset+bytelen],endian)
            if bytelen==0:
                encoding,_=ks.asm(f'mov {r[code[1+offset]]}, [{r[code[2+offset]]}]')
                return bytes(encoding),len(encoding)
            elif bytelen==4:
                suffix='d'
            elif bytelen==2:
                suffix='w'
            elif bytelen==1:
                suffix='b'
            else:
                suffix=''
            encoding,_=ks.asm(f'mov rax, {imm};mov {r[code[1+offset]]}{suffix}, [rax]')
            return bytes(encoding),len(encoding)

        def process_st(offset,bytelen):
            imm=int.from_bytes(code[2+offset:2+offset+bytelen],endian)
            if bytelen==0:
                encoding,_=ks.asm(f'mov [{r[code[1+offset]]}], {r[code[2+offset]]}')
                return bytes(encoding),len(encoding)
            elif bytelen==4:
                suffix='d'
            elif bytelen==2:
                suffix='w'
            elif bytelen==1:
                suffix='b'
            else:
                suffix=''
            encoding,_=ks.asm(f'mov rax, {imm};mov [rax], {r[code[1+offset]]}{suffix}')
            return bytes(encoding),len(encoding)
        
        def process_arith(offset,arith:str,bytelen):
            imm=int.from_bytes(code[2+offset:2+offset+bytelen],endian)
            if bytelen==0:
                if arith=='shr' or arith=='shl':
                    encoding,_=ks.asm(f'mov cl, {r[code[2+offset]]};{arith} {r[code[1+offset]]}, cl')
                    return bytes(encoding),len(encoding)
                else:
                    encoding,_=ks.asm(f'{arith} {r[code[1+offset]]}, {r[code[2+offset]]}')
                    return bytes(encoding),len(encoding)
            elif bytelen==4:
                suffix='d'
            elif bytelen==2:
                suffix='w'
            elif bytelen==1:
                suffix='b'
            else:
                suffix=''
            encoding,_=ks.asm(f'{arith} {r[code[1+offset]]}{suffix}, {imm}')
            return bytes(encoding),len(encoding)
        
        def process_stack_arith(arith:str):
            if arith=='shr' or arith=='shl':
                encoding,_=ks.asm(f'pop rax;pop rcx;{arith} rax, cl;push rax;')
            elif arith=='not':
                encoding,_=ks.asm(f'pop rax;{arith} rax;push rax;')
            else:
                try:
                    encoding,_=ks.asm(f'pop rax;pop rbx;{arith} rax, rbx;push rax;')
                except:
                    print(f'pop rax;pop rbx;{arith} rax, rbx;push rax;')
                    exit(0)
            return bytes(encoding),len(encoding)
        
        def process_stack(offset,bytelen=-1):
            if bytelen==-1:
                encoding,_=ks.asm(f'pop {r[code[1+offset]]}')
                return bytes(encoding),len(encoding)
            elif bytelen==0:
                encoding,_=ks.asm(f'push {r[code[1+offset]]}')
                return bytes(encoding),len(encoding)
            imm=int.from_bytes(code[1+offset:1+offset+bytelen],endian)
            encoding,_=ks.asm(f'mov rax, {imm};push rax')
            return bytes(encoding),len(encoding)
        
        def process_j_obs(offset,condition,bytelen):
            if bytelen==0:
                if condition=='mp':
                    encoding,_=ks.asm(f'j{condition} {r[code[1+offset]]}')
                    return bytes(encoding),len(encoding)
                else:
                    pass # Conditional jump register not implemented
            else:
                imm=int.from_bytes(code[1+offset:1+offset+bytelen],endian)
                jumptable[offset]=imm
                return condition.encode(),6
        
        def process_call_obs(offset,bytelen):
            imm=int.from_bytes(code[1+offset:1+offset+bytelen],endian)
            calltable[offset]=imm
            return b'',6

        def process_io(result):
            if result=="getc":
                encoding,_=ks.asm(f'in ax, 55;')
                return bytes(encoding),len(encoding)
            elif result=="putc":
                encoding,_=ks.asm(f'out 55, ax;')
                return bytes(encoding),len(encoding)

        def process_end(result):
            if result=="success":
                encoding,_=ks.asm(f'mov rax, 0; ret;')
                return bytes(encoding),len(encoding)
            elif result=="fail":
                encoding,_=ks.asm(f'mov rax, 1; ret;')
                return bytes(encoding),len(encoding)
            elif result=="ret":
                encoding,_=ks.asm(f'ret;')
                return bytes(encoding),len(encoding)
            elif result=="check":
                encoding,_=ks.asm(f'pop rax; test ax, ax; jz 0;')
                return bytes(encoding),len(encoding)
        
        def process_nop():
            encoding,_=ks.asm(f'nop')
            return bytes(encoding),len(encoding)
        
        def fill_jumptable():
            for i in jumptable:
                if trans_code.get(jumptable[i]):
                    encoding,_=ks.asm(f'j{trans_code[i][1].decode()} {trans_code[jumptable[i]][0]-trans_code[i][0]}')
                else:
                    encoding=b''
                trans_code[i][1] = bytes(encoding).ljust(6,b'\x90')
        
        def fill_calltable():
            for i in jumptable:
                if trans_code.get(jumptable[i]):
                    encoding,_=ks.asm(f'call {trans_code[jumptable[i]][0]-trans_code[i][0]}')
                else:
                    encoding=b''
                trans_code[i][1] = bytes(encoding).ljust(5,b'\x90')

        while current_vmaddr<len(code):
            opcode=str(code[current_vmaddr])
            trans_code[current_vmaddr]=None
            if ops.get(opcode):
                current_vmaddr+=ops[opcode]["len"]
            else:
                current_vmaddr+=1
        
        current_vmaddr=0
        while current_vmaddr<len(code):
            opcode=str(code[current_vmaddr])
            if ops.get(opcode):
                op=ops[opcode]["name"]
            
                if op=="ldimm8":
                    encoding,codelen=process_ld(current_vmaddr,8)
                elif op=="ldimm4":
                    encoding,codelen=process_ld(current_vmaddr,4)
                elif op=="ldimm2":
                    encoding,codelen=process_ld(current_vmaddr,2)
                elif op=="ldimm1":
                    encoding,codelen=process_ld(current_vmaddr,1)
                elif op=="ldreg":
                    encoding,codelen=process_ld(current_vmaddr,0)
                
                elif op=="stimm8":
                    encoding,codelen=process_st(current_vmaddr,8)
                elif op=="stimm4":
                    encoding,codelen=process_st(current_vmaddr,4)
                elif op=="stimm2":
                    encoding,codelen=process_st(current_vmaddr,2)
                elif op=="stimm1":
                    encoding,codelen=process_st(current_vmaddr,1)
                elif op=="streg":
                    encoding,codelen=process_st(current_vmaddr,0)

                elif op=="addreg":
                    encoding,codelen=process_arith('add',0)

                elif op=="stackadd":
                    encoding,codelen=process_stack_arith('add')
                elif op=="stacksub":
                    encoding,codelen=process_stack_arith('sub')
                elif op=="stackand":
                    encoding,codelen=process_stack_arith('and')
                elif op=="stackor":
                    encoding,codelen=process_stack_arith('or')
                elif op=="stackxor":
                    encoding,codelen=process_stack_arith('xor')
                elif op=="stackshl":
                    encoding,codelen=process_stack_arith('shl')
                elif op=="stackshr":
                    encoding,codelen=process_stack_arith('shr')
                elif op=="stackcmp":
                    encoding,codelen=process_stack_arith('cmp')
                elif op=="stackmul":
                    encoding,codelen=process_stack_arith('imul')
                elif op=="stackdiv":
                    encoding,codelen=process_stack_arith('div')
                elif op=="stacknot":
                    encoding,codelen=process_stack_arith('not')

                elif op=="pushimm8":
                    encoding,codelen=process_stack(current_vmaddr,8)
                elif op=="pushimm4":
                    encoding,codelen=process_stack(current_vmaddr,4)
                elif op=="pushimm2":
                    encoding,codelen=process_stack(current_vmaddr,2)
                elif op=="pushimm1":
                    encoding,codelen=process_stack(current_vmaddr,1)
                elif op=="pushreg":
                    encoding,codelen=process_stack(current_vmaddr,0)
                elif op=="popreg":
                    encoding,codelen=process_stack(current_vmaddr)
                
                elif op=="jr":
                    encoding,codelen=process_j_obs(current_vmaddr,'mp',0)
                elif op[0]=="j":
                    cond=op.split('_')[0][1:]
                    bytelen=int(op[-1])
                    encoding,codelen=process_j_obs(current_vmaddr,cond,bytelen)
                
                elif op=="call":
                    cond=op.split('_')[0][1:]
                    bytelen=int(op[-1])
                    encoding,codelen=process_call_obs(current_vmaddr,cond,bytelen)
    
                elif op=="getc" or op=="putc":
                    encoding,codelen=process_io(op)
                elif op=="success" or op=="fail" or op=="ret" or op=="check":
                    encoding,codelen=process_end(op)

                trans_code[current_vmaddr]=[current_x86addr,encoding]
                current_vmaddr+=ops[opcode]["len"]
                current_x86addr+=codelen

            else:
                encoding,codelen=process_nop()

                trans_code[current_vmaddr]=[current_x86addr,encoding]
                current_vmaddr+=1
                current_x86addr+=codelen
            
        fill_jumptable()
        
        w=b''
        for i in sorted(trans_code):
            w+=trans_code[i][1]
        
        open('bin','wb').write(w)
