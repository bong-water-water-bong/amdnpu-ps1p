# VE2 IPU Firmware ISA Analysis

## Date: 2025-06-29
## Firmware: npu_7.sbin v1.1.2.65 (17f0_11)

---

## Architecture Discovery

The VE2 IPU (Image Processor Unit) uses a **dual-issue 16-bit VLIW ISA** where each 32-bit word contains two 16-bit instructions that execute in parallel.

### Key Statistics
- **28,536 instructions** (32-bit words) in the code section (0x220-0x1c000)
- **39% of all 16-bit halves** have opcode 0x0 (NOP/MOV class)
- **18.7% of 32-bit words** are all-zero (both slots NOP)
- **77.3%** have both slots used
- All 16 bit positions biased toward zero (66-78%) - expected for sparse VLIW encoding

### 16-bit Instruction Format (Hypothesized)
```
Bits [15:12] = opcode (4 bits = 16 major opcodes)
Bits [11:8]  = sub-opcode or dest register (4 bits)
Bits [7:4]   = operand 1 or source register (4 bits)
Bits [3:0]   = operand 2 or immediate (4 bits)
```

### Opcode Distribution
| Opcode | Count | Percentage | Likely Mnemonic |
|--------|-------|-----------|-----------------|
| 0 | 22,252 | 39.0% | NOP, MOV, basic ALU |
| 2 | 4,046 | 7.1% | ARITH/LOGIC (ALU operations) |
| 8 | 3,530 | 6.2% | CONDITIONAL (BEQ, RET) |
| 12 (0xc) | 3,224 | 5.6% | LOAD/MEMORY |
| 1 | 2,454 | 4.3% | ADD/ARITH 2 |
| 9 | 2,482 | 4.3% | TRANSFER/MOVE |
| 4 | 2,583 | 4.5% | MOVE/LOAD ADDR |
| 15 (0xf) | 2,372 | 4.2% | IMMEDIATE/CONSTANT |
| 10 (0xa) | 2,180 | 3.8% | Unclear |
| 6 | 2,266 | 4.0% | VECTOR/COMPLEX |
| 5 | 1,719 | 3.0% | STORE |
| 14 (0xe) | 1,727 | 3.0% | Unclear |
| 11 (0xb) | 1,483 | 2.6% | Unclear |
| 13 (0xd) | 1,323 | 2.3% | Unclear |
| 3 | 2,037 | 3.6% | COMPARE |
| 7 | 1,394 | 2.4% | BRANCH (BRA, BNE) |

### Most Common 16-bit Values
| Value | Count | Description |
|-------|-------|-------------|
| `0x0000` | 11,834 | NOP |
| `0xc090` | 823 | LOAD r9, [r0] (or similar - very common pattern) |
| `0x0001` | 429 | MOV r1, #0 (clear register 1) |
| `0x4136` | 346 | MOV r3, r6 (or similar move) |
| `0x8000` | 344 | RET |
| `0xf01d` | 317 | Large immediate 0x01d |
| `0x1000` | 289 | ADD r0, r0 |

### Branch/Call Patterns
- Calls use format `call 0x0cXX` where 0x0c is a fixed prefix and XX is the target page
- Conditional branches use opcode 7 (BNE-like) and 8 (BEQ-like)
- Branch targets appear to be short (8-bit offset encoded in lower byte)

### String Encoding
String addresses are loaded using instructions with `imm20 = address >> 12` in the upper 20 bits and the lower offset in the lower bits. Example: `0x0001e5f9` loads string at file offset 0x1e5f9 (base 0x1e000 + offset 0x5f9).

### Known Code Locations
| Address | Description |
|---------|-------------|
| 0x0220 | Reset vector / entry point |
| 0x02a0 | Vector table |
| 0x0300 | Boot initialization code |
| 0x0cXX | Core scheduling functions |
| 0x067f0 | Function calling error logging (references 0x3280 area) |
| 0x068ec | Function calling error logging |
| 0x03280-0x03400 | Error logging / string table VLIW packet area |
