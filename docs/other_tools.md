# Other Patching Tools

There are other tools besides `patches`, of course, and some of them might be helpful
to you! Here is a chart of other options and an explanation of how they differ/how
`patches` improves or doesn't improve over them.

| Other Tool                                         | How `patches` differs                                                                                                                     |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| [patcherex](https://github.com/angr/patcherex)     | `patches` is heavily based on `patcherex` but tries to improve by using more modern binary modification libraries and offloads more logic |
| [lief](https://github.com/lief-project/LIEF)       | `patches` uses and builds on top of LIEF, which provides the low-level binary manipulation for `patches`                                  |
| [patchkit](https://github.com/lunixbochs/patchkit) | Not maintained and depends on IDA, which is not free.                                                                                     |
| [e9patch](https://github.com/GJDuck/e9patch)       | C API, only supports a limited use case and is more for rewriting instructions than for changing a binary with patches                    |
| [binch](https://github.com/tunz/binch)             | It's a hex editor really, but it looks nice.                                                                                              |
| [binaryninja](https://binary.ninja)                | Not free, but it has a shellcode compiler and a lot of features in `patches` are inspired by Binja as well as `patcherex`!                |

If you want to just patch one binary and you don't need to do anything at scale, the
best alternative is probably [binaryninja](https://binary.ninja). It has a great UI and
you don't need to write much code to get great patches.

If you do want to patch at scale, for example if you need to patch a bunch of binaries
in the same way, or you are automatically generating patches,
[patcherex](https://github.com/angr/patcherex) or `patches` are your best bets. At the
moment, `patcherex` has a couple features `patches` doesn't: multiple techniques like
detours and reassembling, and it supports more architectures. `patches` on the other
hand is simpler and should be more stable, and handles less of the low level operations
itself. `patches` should also be better at allowing multiple patches to work well
together. Finally, `patches` has a much better shellcode compilation strategy, although
you could very easily use [squishy](https://github.com/novafacing/squishy) with
`patcherex`.
