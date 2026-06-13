"""macOS Mach-O reverse-engineering analyzer.

Parses Mach-O binaries (thin and fat/universal) using only the standard library
to surface what a macOS executable links against and how it is built: linked
dynamic libraries, segment permissions (RWX), whether it carries a code
signature, and whether a region is encrypted (LC_ENCRYPTION_INFO).
"""
from __future__ import annotations

import struct

from .base import Analyzer, AnalyzerResult, FileContext, Severity

# Thin Mach-O magics -> (struct endian prefix, bits).
_THIN_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xcf\xfa\xed\xfe": ("<", 64),  # MH_MAGIC_64 little-endian (modern macOS)
    b"\xce\xfa\xed\xfe": ("<", 32),  # MH_MAGIC little-endian
    b"\xfe\xed\xfa\xcf": (">", 64),  # MH_MAGIC_64 big-endian
    b"\xfe\xed\xfa\xce": (">", 32),  # MH_MAGIC big-endian
}
# Fat/universal magics (big-endian on disk). Note: 0xCAFEBABE collides with Java
# .class files — we validate the structure and bail if it is not a real fat Mach-O.
_FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}

# Load commands of interest.
_LC_REQ_DYLD = 0x80000000
_LC_SEGMENT = 0x01
_LC_SEGMENT_64 = 0x19
_LC_LOAD_DYLIB = 0x0C
_LC_LOAD_WEAK_DYLIB = 0x18 | _LC_REQ_DYLD
_LC_REEXPORT_DYLIB = 0x1F | _LC_REQ_DYLD
_LC_LAZY_LOAD_DYLIB = 0x20
_LC_LOAD_UPWARD_DYLIB = 0x23 | _LC_REQ_DYLD
_DYLIB_CMDS = {
    _LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB,
    _LC_LAZY_LOAD_DYLIB, _LC_LOAD_UPWARD_DYLIB,
}
_LC_CODE_SIGNATURE = 0x1D
_LC_ENCRYPTION_INFO = 0x21
_LC_ENCRYPTION_INFO_64 = 0x2C

_CPU_TYPES = {
    7: "x86", 0x01000007: "x86_64", 12: "ARM", 0x0100000C: "ARM64",
    0x01000012: "PowerPC64", 18: "PowerPC",
}
_FILE_TYPES = {
    1: "object", 2: "executable", 3: "fixed-vm-lib", 4: "core", 5: "preload",
    6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib-stub", 10: "dSYM",
    11: "kext-bundle",
}


class MachOAnalyzer(Analyzer):
    name = "macho"

    def applies(self, ctx: FileContext) -> bool:
        head = ctx.data[:4]
        return head in _THIN_MAGICS or head in _FAT_MAGICS

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        data = ctx.data
        head = data[:4]

        try:
            if head in _FAT_MAGICS:
                base = self._fat_first_slice(data)
                if base is None:
                    result.metadata = {"is_macho": False}
                    return result  # likely a Java .class or malformed fat header
                result.metadata["fat"] = True
            else:
                base = 0
            self._parse_thin(data, base, result)
        except (struct.error, IndexError, ValueError) as exc:
            result.metadata = {"is_macho": False, "detail": str(exc)}
            return result

        return result

    # ------------------------------------------------------------------ #
    def _fat_first_slice(self, data: bytes) -> int | None:
        # fat_header: magic (BE), nfat_arch (BE).
        if len(data) < 8:
            return None
        nfat = struct.unpack_from(">I", data, 4)[0]
        if not (1 <= nfat <= 32):  # implausible -> not a fat Mach-O (e.g. Java class)
            return None
        # fat_arch: cputype, cpusubtype, offset, size, align (all uint32 BE).
        off, size = struct.unpack_from(">II", data, 8 + 8)  # offset, size fields
        if off <= 0 or off + 4 > len(data) or size <= 0:
            return None
        if data[off:off + 4] not in _THIN_MAGICS:
            return None
        return off

    def _parse_thin(self, data: bytes, base: int, result: AnalyzerResult) -> None:
        magic = data[base:base + 4]
        endian, bits = _THIN_MAGICS[magic]
        hdr_size = 32 if bits == 64 else 28
        (
            _magic, cputype, _cpusub, filetype, ncmds, _sizeofcmds, _flags,
        ) = struct.unpack_from(endian + "IIIIIII", data, base)

        meta = result.metadata
        meta.update(
            {
                "is_macho": True,
                "bits": bits,
                "endian": "little" if endian == "<" else "big",
                "arch": _CPU_TYPES.get(cputype, hex(cputype)),
                "filetype": _FILE_TYPES.get(filetype, str(filetype)),
            }
        )

        dylibs: list[str] = []
        signed = False
        encrypted = False
        rwx = False

        off = base + hdr_size
        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
            if cmdsize < 8 or off + cmdsize > len(data):
                break

            if cmd in _DYLIB_CMDS:
                name_off = struct.unpack_from(endian + "I", data, off + 8)[0]
                start = off + name_off
                end = data.find(b"\x00", start, off + cmdsize)
                if start < off + cmdsize and end != -1:
                    dylibs.append(data[start:end].decode("utf-8", "ignore"))
            elif cmd == _LC_CODE_SIGNATURE:
                signed = True
            elif cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64):
                cryptid = struct.unpack_from(endian + "I", data, off + 16)[0]
                if cryptid != 0:
                    encrypted = True
            elif cmd in (_LC_SEGMENT, _LC_SEGMENT_64):
                initprot_off = off + (60 if cmd == _LC_SEGMENT_64 else 44)
                if initprot_off + 4 <= off + cmdsize:
                    initprot = struct.unpack_from(endian + "I", data, initprot_off)[0]
                    if (initprot & 0x2) and (initprot & 0x4):  # WRITE and EXECUTE
                        rwx = True

            off += cmdsize

        meta["dylibs"] = dylibs
        meta["dylib_count"] = len(dylibs)
        meta["code_signature"] = signed
        meta["encrypted"] = encrypted
        meta["rwx_segment"] = rwx

        runnable = filetype in (2, 6, 8)  # executable / dylib / bundle
        if runnable and not signed:
            result.add(
                id="macho.unsigned",
                title="Mach-O binary has no code signature",
                description=(
                    "The macOS binary carries no LC_CODE_SIGNATURE load command, so "
                    "it is unsigned. macOS Gatekeeper blocks unsigned binaries by "
                    "default; legitimate distributed software is signed and notarised."
                ),
                severity=Severity.LOW,
                category="executable",
            )
        if encrypted:
            result.add(
                id="macho.encrypted",
                title="Mach-O contains an encrypted region",
                description=(
                    "A segment is marked encrypted (LC_ENCRYPTION_INFO cryptid set). "
                    "Outside of App Store binaries this is used to hide code from "
                    "static analysis."
                ),
                severity=Severity.MEDIUM,
                category="executable",
            )
        if rwx:
            result.add(
                id="macho.rwx_segment",
                title="Writable + executable Mach-O segment",
                description=(
                    "A segment is both writable and executable, allowing the binary "
                    "to generate and run code at runtime — a loader/packer trait."
                ),
                severity=Severity.MEDIUM,
                category="executable",
            )
