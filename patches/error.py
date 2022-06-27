"""
Errors specific to the patches package.
"""


class CompilationError(Exception):
    """
    An error that occurs when a snippet of C/C++ code fails to compile
    """


class TransformationError(Exception):
    """
    An error that occurs when transformation of LLVM bitcode using the
    shellvm wrapper fails
    """


class CodegenError(Exception):
    """
    An error that occurs when code generation fails
    """


class BinaryCreateError(Exception):
    """
    An error that occurs when a binary code file cannot be produced
    """


class NoSectionError(Exception):
    """
    An error that occurs when a section is not found
    """
