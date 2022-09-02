# Installing Patches

## Dependencies

Patches has no binary or library dependencies, but it does depend on
[squishy](https://github.com/novafacing/squishy), which does have a couple dependencies.

### Meson and Ninja

You can install meson and ninja with your package manager:

```sh
$ sudo apt-get install meson ninja-build
```

### Clang 15.0

`squishy` specifically depends on LLVM and Clang >= 15.0.0 (although this may be relaxed
in the future). The easiest way to install this specific version is using the LLVM APT:

```sh
$ wget -qO - wget -O - https://apt.llvm.org/llvm.sh | bash -s 15 all
```

`squishy` also requires the executable returned by `which clang` to be `clang-15`. You
can set this manually with a symbolic link, but you should just run the alternatives
script provided with `squishy`, which you can find [here](https://github.com/novafacing/squishy/blob/main/scripts/set-alternatives.sh)

## From PyPI

Patches can be installed from PyPI directly:

```sh
$ python3 -m pip install pypatches
```

## From git

Patches can also be installed from git:

```sh
$ python3 -m pip install git+https://github.com/novafacing/patches.git
```

## Manually

Patches can also be installed manually:

```sh
$ git clone https://github.com/novafacing/patches.git
$ cd patches
$ poetry install
```

