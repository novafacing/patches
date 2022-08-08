# PyPatches Documentation


PyPatches is a library that aims to make binary patching easy!

## Patch Strategies

- Replace Code: Assemble code directly over the existing binary
- Nop Code: Make code not do something
- Invert/always/never branch: Make branch always/never/go the opposite way it does right now
- Replace Function at Callsites: Change calls to a function to call elsewhere -- either
  replace all or just some calls
- Replace Function: Make a function do something else
- Add data: add global data to a program
- Hook extern: change the contents of a got/plt entry

## Dependencies

PyPatches uses the following libraries and packages, each for their intended purpose:

- archinfo: For architecture information about the binary's architecture
- cle: For loading, segment/section information, symbols
- angr: For program analysis, identification of branches and functions
- lief: For ELF parsing and modification

## VS Existing Solutions

- patcherex: This aims to simplify patcherex a bit, but it works well a lot of the time.
- lief: Provides some patching functionality but nothing super hardcore
- patchkit: It's not really maintained
- e9patch: It's in C and only works on x86_64 :(
- backdoor factory: Only for psexec basically
- binch: You have to write the asm inline


## Examples

Probably the best source of examples is the `pypatches/test` directory. It will have
up-to-date tests of each feature of the library that can be used as a jumping-off
point for using the library. Here are a few small examples to get you started:

### Common usage and NOP patching

Say we have a binary `test-bin` that calls `ptrace` as an anti-debugging measure to stop
would-be reverse engineers from debugging it. We can quickly defeat this technique:

```python
from pathlib import Path
from pypatches.patcher import Patcher
from pypatches.patches import NopPatch
from pypatches.types import AddressRange

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

We'll now have a program with our anti-debugging `ptrace` calls removed! `pypatches` uses
angr to take care of a lot of the dirty work, so we don't have to worry about compiling
the assembly ourselves, picking the right nop instruction, etc.

### Add a function and redirect calls

A slightly more advanced usage of `pypatches` allows us to add a function and redirect
calls to some function, for example, malloc, to our own function instead. We'll patch
a program that uses malloc to redirect those malloc calls to our function that will log
all of the allocations it makes before proxying the malloc call.

Note: the below example is incomplete for now.

```python
from pathlib import Path
from pypatches.patcher import Patcher
from pypatches.patches import AddCodePatch, ReplaceCodePatch
from pypatches.types import AddressRange

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

::: pypatches.patcher
::: pypatches.patches
::: pypatches.binary_manager
::: pypatches.types
::: pypatches.error
::: pypatches.dynamic_info.py
::: pypatches.util.cs_memop_eq