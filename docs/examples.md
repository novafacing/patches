# Patches examples/recipes

First, some super basic examples. Again, you are highly recommended to check out the
test cases as they will be up to date! You can find them in the
[test directory](https://github.com/novafacing/patches/tree/main/test).

## Super Basic

## NOP out code at a specific address

```python
from pypatches.patcher import Patcher
from pypatches.patches import NopPatch
from pypatches.address_range import AddressRange

# Nop specific addresses
np = NopPatch(addresses=[0x400000, 0x400001])
# Nop a range of addresses
np2 = NopPatch(address_ranges={AddressRange(0x400000, 0x400fff)})

# Create a patcher for the binary
patcher = Patcher("./binary")

# Add patches
patcher.apply(np)
patcher.apply(np2)

# Apply patches and save binary
# Protip: You can use `pathlib.Path`s here instead of strings!
patcher.save("./binary.patched")
```

### Add data to the binary

```python
from pypatches.patcher import Patcher
from pypatches.patches import DataPatch
from string import printable

dp = DataPatch(
    bytes(printable, "utf-8"),
    read=True,
    write=True,
    exec=False,
    label="chars"
)

patcher = Patcher("./binary")

patcher.apply(dp)

patcher.save("./binary.patched")
```

### Replace some code

```python
from pypatches.patcher import Patcher
from pypatches.patches import ReplaceCodePatch
from pypatches.code import build_c_code

code = build_c_code(
    """
    /* You can write pretty complex C here but I'm lazy */
    for (size_t i = 0; i < 10; i++) {
        i++;
    }
    return 1;
    """
    includes=["#include <stdint.h>", "#include <stddef.h>"]
)

# Notice that we're gonna replace `main` with this code!
rcp = ReplaceCodePatch(code, address=lambda t: t.lief_binary.get_symbol("main").value)

patcher = Patcher("./binary")

patcher.apply(rcp)

patcher.save("./binary.patched")
```
