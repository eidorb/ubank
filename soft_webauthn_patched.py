"""
Patches the source of soft_webauthn module so that user verification (UV) bits
are always set.

"How to modify imported source code on-the-fly?": https://stackoverflow.com/a/41863728/1660046
"""

import sys
from importlib import util


def modify_and_import(module_name, package, modification_func):
    spec = util.find_spec(module_name, package)
    source = spec.loader.get_source(module_name)
    new_source = modification_func(source)
    module = util.module_from_spec(spec)
    codeobj = compile(new_source, module.__spec__.origin, "exec")
    exec(codeobj, module.__dict__)
    sys.modules[module_name] = module
    return module


def patch_flags(source: str):
    """Enables User Verification (UV) bit in create() and get() methods' bit flags.

    Bit flag info: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
    """
    source = (
        source
        # patch bit flags in .create()
        .replace(r"flags = b'\x41'", r"flags = b'\x45'")
        # and .get()
        .replace(r"flags = b'\x01'", r"flags = b'\x05'")
    )
    return source


soft_webauthn = modify_and_import("soft_webauthn", "soft_webauthn", patch_flags)
SoftWebauthnDevice = soft_webauthn.SoftWebauthnDevice
