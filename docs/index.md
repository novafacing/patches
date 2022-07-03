# Patches Documentation


Patches is a library that aims to make binary patching easy!


## Examples

Probably the best source of examples is the `patches/test` directory. It will have
up-to-date tests of each feature of the library that can be used as a jumping-off
point for using the library. Here are a few small examples to get you started:

### Common usage and NOP patching

Say we have a binary `test-bin` that calls `ptrace` as an anti-debugging measure to stop
would-be reverse engineers from debugging it. We can quickly defeat this technique:

```python
from pathlib import Path
from patches.patcher import Patcher
from patches.patches import NopPatch
from patches.types import AddressRange

# Make a path to the binary
bin = Path("./test-bin")
# Create a patcher with the default options
pat = Patcher(bin)
# The patcher's `binary` attribute has the binary loaded with angr and LIEF:
lief_bin = pat.binary.lief_binary
angr_proj = pat.binary.angr_project
# Use angr to find some places we want to patch, 
# maybe we will remove all calls to ptrace
ranges = set()
for func in angr_proj.kb.functions.values():
    for block in func.blocks:
        if (
            block.vex.jumpkind == "Ijk_Call" 
            and angr_proj.kb.functions.get(
                next(iter(block.vex.constant_jump_targets))
            ).name == "ptrace"
        ):
            insn = block.disassembly.insns[-1]
            ranges.add(AddressRange(insn.address, insn.address + insn.size))

# Now we want to make a Nop Patch that will nop out all those ptrace calls in one go
patch = NopPatch(address_ranges=ranges)
pat.apply(patch)
pat.save(bin.with_name(bin.name + ".patched"))
```

We'll now have a program with our anti-debugging `ptrace` calls removed! `patches` uses
angr to take care of a lot of the dirty work, so we don't have to worry about compiling
the assembly ourselves, picking the right nop instruction, etc.

### Add a function and redirect calls

A slightly more advanced usage of `patches` allows us to add a function and redirect
calls to some function, for example, malloc, to our own function instead. We'll patch
a program that uses malloc to redirect those malloc calls to our function that will log
all of the allocations it makes before proxying the malloc call.

Note: the below example is incomplete for now.

```python
from pathlib import Path
from patches.patcher import Patcher
from patches.patches import AddCodePatch, ReplaceCodePatch
from patches.types import AddressRange

# Make a path to the binary
bin = Path("./test-bin")
# Create a patcher with the default options
pat = Patcher(bin)
# The patcher's `binary` attribute has the binary loaded with angr and LIEF:
lief_bin = pat.binary.lief_binary
angr_proj = pat.binary.angr_project

callers = set()
for func in angr_proj.kb.functions.values():
    for block in func.blocks:
        if (
            block.vex.jumpkind == "Ijk_Call" 
            and angr_proj.kb.functions.get(
                next(iter(block.vex.constant_jump_targets))
            ).name == "malloc"
        ):
            insn = block.disassembly.insns[-1]
            callers.add(insn.address)

# Create a wrapper patch -- the below code will be placed into a function body, compiled, and mapped
# as an executable segment and can be referenced from the "malloc_hook" label
malloc_hook_code = Code(
    c_code=Code.build_c_code(malloc_wrapper_code, getreg_helper=True),
)
malloc_hook_patch = AddCodePatch(malloc_hook_code, label="malloc_hook")

pat.apply(malloc_hook_patch)

def transformer(asm: str, tinfo: TransformInfo) -> str:


for caller in callers:
    replace_call_patch = ReplaceCodePatch(Code(assembly="call {malloc_hook}"), transform_asm=transformer)
```












## API Reference

::: patches.patcher
::: patches.patches
::: patches.binary_manager
::: patches.types
::: patches.error
::: patches.util.cs_memop_eq
::: patches.shellvm.wrapper