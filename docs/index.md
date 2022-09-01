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


## Design

Patches in `patches` are a somewhat abstract concept and refer moreso to the idea of
a "single change to a binary" than to a specific swap of bytes in a specific location.

For example: "replace 1 byte at 0x401000 with 0x90" is a patch, and so is "compile this
C code and add it somewhere I can jump to it at label `my_code`" and so is "add this
long string somewhere at label `my_string`".

Patches doesn't try to be too clever: it very much believes patching is a low level and
application specific process, so it doesn't want to get in your way. C, asm, and raw
bytes will always be equally supported. For C, patches uses
[squishy](https://github.com/novafacing/squishy.git), my LLVM-based shellcode compiler
to allow nearly arbitrary C code to be compiled into a big blob and jumped to.

## Patching Process

When a patch is applied with `patcher.apply_xxx()`, nothing immediately changes. The
patch is basically "queued" for application when `patcher.save` is called later to write
changes to disk. There are two reasons for this:

1. Patches *must* work together! We rarely just want to change one thing!
2. It is easier from a programming perspective :)

Patches are *created* without context, but they are applied with context. This can look
a little weird at first, because a set of patches might look something like:

```python
d = DataPatch(
    b"hello\n\x00", read=True, write=True, exec=False, label="hellostr"
)
p = AddCodePatch(
    code=(
        "mov rdi, {hellostr_addr}\n"
        "call {puts_plt}\n"
    ),
    dummy_transformer=lambda asm: sub(r"\{[a-z_]+\}", "0", asm),
    build_transformer=lambda tinfo, code: code.format(
        hellostr_addr=tinfo.data_offsets.get("hellostr"), 
        puts_plt=tinfo.lief_binary.get_symbol("puts").value
    )
)
```

That is pretty odd looking, but there is a method to the madness. 

1. The code is "transformed" with the `dummy_transformer` (which, if you don't provide one, will just
   return the asm which may be OK for your purposes!). This is used to figure out how big
   the code is (a fudge factor of 2 is added for safety). 
2. The patcher "dummy transforms" all the code it needs to add, and modifies the binary
   with new segments large enough to hold all the new code and data it will be adding.
3. The patcher "transforms" the code again with the `build_transformer`, this time
   providing the binary context which contains the offsets of all the data and code
   we added, indexed by label, the binary information from LIEF (and angr, not pictured)
   and some other extra info. This allows us to perform any relocating or fixing up we
   need to do so our code will call the right locations and such in the final binary!


## Examples

There are some examples [here](examples.md), but the most up to date examples will
be in the [test directory](https://github.com/novafacing/patches/tree/main/test).

## API Reference

You can get the raw unfiltered API reference [here](api.md).