# Patches

Patches is a patching library for patching binaries using various strategies, and it
tries not to make you [guess](https://github.com/angr/patcherex) what is going on...

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

Patches uses the following libraries and packages, each for their intended purpose:

- archinfo: For architecture information about the binary's architecture
- cle: For loading, segment/section information, symbols
- angr: For program analysis, identification of branches and functions
- lief: For ELF parsing and modification

## Existing Solutions

- patcherex: This aims to simplify patcherex a bit, but it works well a lot of the time.
- lief: Provides some patching functionality but nothing super hardcore
- patchkit: It's not really maintained
- e9patch: It's in C and only works on x86_64 :(
- backdoor factory: Only for psexec basically
- binch: You have to write the asm inline