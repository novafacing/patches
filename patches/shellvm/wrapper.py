"""
Shellvm wrapper utilities
"""

from pathlib import Path
from subprocess import CalledProcessError, run
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Optional, Union
from logging import getLogger

from patches.error import (
    CompilationError,
    TransformationError,
    CodegenError,
    BinaryCreateError,
)

SHELLVM_SO_PATH = Path(__file__).with_name("shellvm.so")
logger = getLogger(__name__)


def get_shellvm_so_path() -> Path:
    """
    Get the path to the shellvm shared object
    """
    if not SHELLVM_SO_PATH.is_file():
        logger.error(
            "shellvm.so not found! Please compile shellvm before using patches by "
            "running `build.py`, although this should be done automatically "
            "when installing patches"
        )
        raise FileNotFoundError("shellvm.so not found")

    return SHELLVM_SO_PATH


class SheLLVM:
    """
    Shellvm wrapper class
    """

    @classmethod
    def test_command(cls, command: str) -> None:
        """
        Test a command
        """
        cmd = [command, "--version"]
        try:
            run(cmd, capture_output=True, check=True)
        except CalledProcessError as e:
            raise FileNotFoundError(f"{command} not found") from e

    def __init__(
        self,
        cc: str = "clang",
        opt: str = "opt",
        llvm_link: str = "",  # Currently unused but is required to use any libraries (windows)
        llvm_dis: str = "",  # Set if you want to see the bitcode for debugging
        objcopy: str = "objcopy",
    ) -> None:
        """
        Set up wrapper and check that we have everything we need. Overriding the default
        commands should not be necessary, but may be done if for example you have
        installed clang from apt.llvm.org and it is installed as `/usr/bin/clang-15` or
        some such thing. Alternatively, on debian based distributions, run:

        ```
        sudo update-alternatives --install \
            /usr/bin/clangd clangd $(which clangd-15) 100
        sudo update-alternatives --install \
            /usr/bin/clang clang $(which clang-15) 100
        sudo update-alternatives --install \
            /usr/bin/clang++ clang++ $(which clang++-15) 100
        sudo update-alternatives --install \
            /usr/bin/clang-tidy clang-tidy $(which clang-tidy-15) 100
        sudo update-alternatives --install \
            /usr/bin/clang-format clang-format $(which clang-format-15) 100
        sudo update-alternatives --install \
            /usr/bin/lld lld $(which lld-15) 100
        sudo update-alternatives --install \
            /usr/bin/llvm-link llvm-link $(which llvm-link-15) 100
        sudo update-alternatives --install \
            /usr/bin/llc llc $(which llc-15) 100
        sudo update-alternatives --install \
            /usr/bin/opt opt $(which opt-15) 100
        sudo update-alternatives --install \
            /usr/bin/llvm-dis llvm-dis $(which llvm-dis-15) 100
        sudo update-alternatives --install \
            /usr/bin/llvm-symbolizer llvm-symbolizer $(which llvm-symbolizer-15) 100
        ```

        :param cc: clang compiler command
        :param opt: opt optimizer command
        :param llvm_link: llvm-link linker command
        :param llvm_dis: llvm-dis disassembler command -- if this option is set to a
            non-empty string, the produced LLVM bitcode will be logged to the debug log
        :param objcopy: objcopy object file copier command
        """
        self.test_command(cc)
        self.test_command(opt)

        if llvm_link:
            self.test_command(llvm_link)

        if llvm_dis:
            self.test_command(llvm_dis)

        self.test_command(objcopy)
        self.cc = cc
        self.opt = opt
        self.llvm_link = llvm_link
        self.llvm_dis = llvm_dis
        self.objcopy = objcopy
        self.so_path = get_shellvm_so_path()

    def compile(
        self,
        code: Union[str, bytes],
        arch: str = "",
        vendor: str = "",
        os: str = "",
        environment: str = "",
        extra_run_args: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Compile code with shellvm into a binary region that can be jumped to to execute.

        The "original list" of these options is
        [here](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Support/Triple.cpp),
        but they are written below for an easier-to-use reference:

        :param arch: The arch string from the target platform triple.
            The majority of arch strings are:
            * i386
            * i486
            * i586
            * i686
            * i786
            * i886
            * i986
            * amd64
            * x86_64
            * x86_64h
            * powerpc
            * powerpcspe
            * ppc
            * ppc32
            * powerpcle
            * ppcle
            * ppc32le
            * powerpc64
            * ppu
            * ppc64
            * powerpc64le
            * ppc64le
            * xscale
            * xscaleeb
            * aarch64
            * aarch64_be
            * aarch64_32
            * arc
            * arm64
            * arm64_32
            * arm64e
            * arm
            * armeb
            * thumb
            * thumbeb
            * avr
            * m68k
            * msp430
            * mips
            * mipseb
            * mipsallegrex
            * mipsisa32r6,
            * mipsr6
            * mipsel
            * mipsallegrexel
            * mipsisa32r6el
            * mipsr6el,
            * mips64
            * mips64eb
            * mipsn32
            * mipsisa64r6,
            * mips64r6
            * mipsn32r6
            * mips64el
            * mipsn32el
            * mipsisa64r6el
            * mips64r6el,
            * mipsn32r6el
            * r600
            * amdgcn
            * riscv32
            * riscv64
            * hexagon
            * s390x
            * systemz
            * sparc
            * sparcel
            * sparcv9
            * sparc64
            * tce
            * tcele
            * xcore
            * nvptx
            * nvptx64
            * le32
            * le64
            * amdil
            * amdil64
            * hsail
            * hsail64
            * spir
            * spir64
            * spirv32
            * spirv32v1.0
            * spirv32v1.1
            * spirv32v1.2,
            * spirv32v1.3
            * spirv32v1.4
            * spirv32v1.5
            * spirv64
            * spirv64v1.0
            * spirv64v1.1
            * spirv64v1.2,
            * spirv64v1.3
            * spirv64v1.4
            * spirv64v1.5
            * lanai
            * renderscript32
            * renderscript64
            * shave
            * ve
            * wasm32
            * wasm64
            * csky
            * loongarch32
            * loongarch64
            * dxil

        :param vendor: The vendor string from the target platform triple.
            The majority of vendor strings are:
            * apple
            * pc
            * scei
            * sie
            * fsl
            * ibm
            * img
            * mti
            * nvidia
            * csr
            * myriad
            * amd
            * mesa
            * suse
            * oe

        :param os: The os string from the target platform triple.
            The majority of os strings are:
            * ananas
            * cloudabi
            * darwin
            * dragonfly
            * freebsd
            * fuchsia
            * ios
            * kfreebsd
            * linux
            * lv2
            * macos
            * netbsd
            * openbsd
            * solaris
            * win32
            * windows
            * zos
            * haiku
            * minix
            * rtems
            * nacl
            * aix
            * cuda
            * nvcl
            * amdhsa
            * ps4
            * ps5
            * elfiamcu
            * tvos
            * watchos
            * driverkit
            * mesa3d
            * contiki
            * amdpal
            * hermit
            * hurd
            * wasi
            * emscripten
            * shadermodel

        :param environment: The environment string from the target platform triple.
            The majority of environment strings are:
            * eabihf
            * eabi
            * gnuabin32
            * gnuabi64
            * gnueabihf
            * gnueabi
            * gnux32
            * gnu_ilp32
            * code16
            * gnu
            * android
            * musleabihf
            * musleabi
            * muslx32
            * musl
            * msvc
            * itanium
            * cygnus
            * coreclr
            * simulator
            * macabi
            * pixel
            * vertex
            * geometry
            * hull
            * domain
            * compute
            * library
            * raygeneration
            * intersection
            * anyhit
            * closesthit
            * miss
            * callable
            * mesh
            * amplification
        ```
        """

        if extra_run_args is None:
            extra_run_args = {}

        if isinstance(code, str):
            code = code.encode("utf-8")

        triple = (
            f"{arch + '-' if arch else arch}"
            f"{vendor + '-' if vendor else vendor}"
            f"{os + '-' if os else os}"
            f"{environment + '-' if environment else environment}"
        )

        try:
            bitcode = run(
                [
                    self.cc,
                    "-target",
                    triple,
                    "-c",
                    "-emit-llvm",
                    # Language is C
                    "-x",
                    "c",
                    # Output to stdout
                    "-o",
                    "-",
                    # Input from stdin
                    "-",
                ],
                check=True,
                input=code,
                capture_output=True,
                **extra_run_args,
            ).stdout
        except CalledProcessError as e:
            logger.error("Compilation failed with error(s):")

            for line in e.stderr.decode("utf-8").splitlines():
                logger.error(line)

            raise CompilationError("Unable to produce bitcode") from e

        try:
            opt_bitcode = run(
                [
                    self.opt,
                    "-load",
                    f"{str(self.so_path.resolve())}",
                    "--shellvm-prepare",
                    "--shellvm-precheck",
                    "--shellvm-flatten",
                    "--shellvm-global2stack",
                    "--shellvm-inlinectors",
                    "--shellvm-postcheck",
                    "-enable-new-pm=0",
                    "-f",
                    # Input from stdin
                    "-",
                ],
                check=True,
                input=bitcode,
                capture_output=True,
                **extra_run_args,
            ).stdout

            if self.llvm_dis:
                human_opt_bitcode = run(
                    [
                        self.llvm_dis,
                        "-",
                    ],
                    check=False,
                    input=bitcode,
                    capture_output=True,
                ).stdout.decode("utf-8")

                logger.debug("Produced transformed bitcode from from C code:")

                for line in human_opt_bitcode.splitlines():
                    logger.debug(line)

        except CalledProcessError as e:
            logger.error("Transformation failed with error(s):")

            for line in e.stderr.decode("utf-8").splitlines():
                logger.error(line)

            raise TransformationError("Failed to transform bitcode") from e

        output_path = NamedTemporaryFile(suffix=".bin", delete=False)
        elf_path = Path(output_path.name)

        try:
            run(
                [
                    self.cc,
                    "-target",
                    triple,
                    "-Oz",
                    "-s",
                    "-x",
                    "ir",
                    "-o",
                    f"{output_path.name}",
                    # Input from stdin
                    "-",
                ],
                check=True,
                input=opt_bitcode,
                capture_output=True,
                **extra_run_args,
            )
        except CalledProcessError as e:
            elf_path.unlink(missing_ok=True)
            raise CodegenError("Failed to generate an ELF file") from e

        elf_text_path = Path(output_path.name + ".text")

        try:
            run(
                [
                    self.objcopy,
                    "-O",
                    "binary",
                    "--only-section=.text",
                    str(elf_path),
                    str(elf_text_path),
                ],
                check=True,
                capture_output=True,
                **extra_run_args,
            )

        except CalledProcessError as e:
            elf_path.unlink(missing_ok=True)
            elf_text_path.unlink(missing_ok=True)
            raise BinaryCreateError("Failed to obtain a text section as binary") from e

        code_output = elf_text_path.read_bytes()

        elf_path.unlink(missing_ok=True)
        elf_text_path.unlink(missing_ok=True)

        logger.info(f"Produced ELF file with {len(code_output)} bytes.")

        return code_output
