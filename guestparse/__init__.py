"""
guestparse - rekonstrukcia objektov hosta z pamatovej snimky zberaca.

Balik cita snimky vmicollect (.vmicd alebo raw) a profil jadra hosta
(kallsyms + BTF) a vracia procesy, moduly a sietove spojenia. V hostovi
nebezi ziadny agent - jedina vstupna znalost je profil jadra, ziskany raz a
mimo behu zberu.

Zavisi iba od standardnej kniznice.

Povod: balik vznikol 2026-09-18 rozdelenim prototypu vmi_parse.py z pripravnej
fazy do modulov. Prototyp bol overeny nad realnou snimkou domeny hyptcn-guest;
co presne sa prevzalo a co pribudlo, je v docs/ARCHITEKTURA.md.
"""

from .checks import check_all
from .image import (PAGE, ChainError, RawImage, VmicdImage, chain_files,
                    open_image, validate_chain)
from .profile import Profile, ProfileError, btf_offsets
from .view import GuestView, build_view

__all__ = [
    "PAGE", "ChainError", "RawImage", "VmicdImage", "chain_files",
    "open_image", "validate_chain",
    "Profile", "ProfileError", "btf_offsets",
    "GuestView", "build_view",
    "check_all",
]

__version__ = "0.1.0"
