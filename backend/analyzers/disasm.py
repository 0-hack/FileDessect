"""Disassembly & assembly-level threat analyzer.

Disassembles a compiled binary's entry point with the Capstone engine — the
same disassembly engine family that powers the Rizin/Cutter reverse-engineering
suite — and flags suspicious machine-code constructs that source- or
import-level analysis cannot see:

  * PEB access (``fs:[0x30]`` / ``gs:[0x60]``) used by shellcode to locate
    modules and resolve APIs by hash;
  * direct ``syscall`` / ``sysenter`` stubs that bypass API hooks (EDR evasion);
  * anti-analysis instructions (``rdtsc`` timing, ``cpuid`` VM probing);
  * embedded ``INT3`` breakpoint runs and ``NOP`` sleds (shellcode markers);
  * stack pivots used by ROP chains.

The annotated entry-point listing is returned for display so the user can read
the assembly directly. For full function-level structure (function listing,
import call sites, decompilation) the companion :mod:`~backend.analyzers.cutter`
analyzer drives the Rizin engine when the ``rizin`` binary is installed.
"""
from __future__ import annotations

import io
import re

from .base import Analyzer, AnalyzerResult, FileContext, Severity

try:
    import capstone  # type: ignore

    _HAVE_CAPSTONE = True
except Exception:  # pragma: no cover
    _HAVE_CAPSTONE = False

try:
    import pefile  # type: ignore

    _HAVE_PEFILE = True
except Exception:  # pragma: no cover
    _HAVE_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile  # type: ignore

    _HAVE_ELF = True
except Exception:  # pragma: no cover
    _HAVE_ELF = False

# How much code to disassemble from the entry point, and the listing cap.
_WINDOW_BYTES = 4096
_MAX_INSNS = 500

# Registers that, as a call/jmp target, mean indirect (computed) control flow.
_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10",
    "r11", "r12", "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi",
}

# Raw-byte opcode signatures, scanned across the executable sections.
_BYTE_SIGS: dict[str, tuple[re.Pattern[bytes], str, Severity, str]] = {
    "peb_x64": (
        re.compile(rb"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"),
        "PEB access via gs:[0x60]",
        Severity.HIGH,
        "x64 shellcode reads the PEB to enumerate loaded modules / resolve APIs.",
    ),
    "peb_x86": (
        re.compile(rb"\x64\xa1\x30\x00\x00\x00"),
        "PEB access via fs:[0x30]",
        Severity.HIGH,
        "x86 shellcode reads the PEB to enumerate loaded modules / resolve APIs.",
    ),
    "nop_sled": (
        re.compile(rb"\x90{16,}"),
        "NOP sled",
        Severity.MEDIUM,
        "A long run of single-byte NOPs is a classic landing pad for injected "
        "shellcode (compilers emit multi-byte NOPs, not long 0x90 runs).",
    ),
    # Note: runs of 0xCC (INT3) are deliberately NOT treated as suspicious — they
    # are overwhelmingly benign inter-function alignment padding emitted by
    # linkers, and flagging them produces false positives on clean binaries.
}


class DisassemblyAnalyzer(Analyzer):
    name = "disasm"

    def applies(self, ctx: FileContext) -> bool:
        if not _HAVE_CAPSTONE:
            return False
        head = ctx.data[:4]
        return head[:2] == b"MZ" or head == b"\x7fELF"

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        if not _HAVE_CAPSTONE:
            result.error = "capstone not installed; disassembly unavailable"
            return result

        try:
            loaded = self._load(ctx)
        except Exception as exc:  # malformed binary
            result.error = f"could not locate code to disassemble: {exc}"
            return result
        if loaded is None:
            result.error = "unsupported architecture for disassembly"
            return result

        code, entry_va, archkey, exec_bytes = loaded
        md = self._capstone_for(archkey)
        if md is None:
            result.error = f"unsupported architecture: {archkey}"
            return result
        md.detail = False

        listing: list[dict] = []
        category_counts: dict[str, int] = {}
        for ins in md.disasm(code[:_WINDOW_BYTES], entry_va):
            flag = _classify_instruction(ins.mnemonic, ins.op_str)
            if flag:
                category_counts[flag[0]] = category_counts.get(flag[0], 0) + 1
            listing.append(
                {
                    "addr": f"0x{ins.address:x}",
                    "bytes": ins.bytes.hex(),
                    "mnemonic": ins.mnemonic,
                    "op_str": ins.op_str,
                    "flag": flag[0] if flag else None,
                    "note": flag[2] if flag else None,
                }
            )
            if len(listing) >= _MAX_INSNS:
                break

        # Byte-pattern signature scan over all executable bytes.
        sig_hits: dict[str, int] = {}
        for key, (pat, _title, _sev, _why) in _BYTE_SIGS.items():
            n = len(pat.findall(exec_bytes))
            if n:
                sig_hits[key] = n

        result.metadata = {
            "engine": "capstone",
            "architecture": archkey,
            "entry_point": f"0x{entry_va:x}",
            "instructions_shown": len(listing),
            "disassembly": listing,
            "instruction_flags": category_counts,
            "signature_hits": sig_hits,
        }

        runtime = ctx.metadata.get("runtime")
        self._emit_findings(result, category_counts, sig_hits, archkey, runtime)
        return result

    # ------------------------------------------------------------------ #
    def _emit_findings(self, result, cat_counts, sig_hits, archkey, runtime=None) -> None:
        # In Go/Rust binaries, byte-scan NOP runs and SP-writes are runtime stack
        # management / padding, not shellcode — report them as INFO so they stay
        # visible without inflating the score.
        _downweight = runtime in ("go", "rust")

        # Byte-signature based findings (highest confidence).
        for key, count in sig_hits.items():
            _pat, title, sev, why = _BYTE_SIGS[key]
            if _downweight and key == "nop_sled":
                sev = Severity.INFO
                why += (
                    f" (Reported as informational: this is a {runtime} binary, "
                    "where such runs are typically runtime padding rather than a "
                    "shellcode sled.)"
                )
            result.add(
                id=f"disasm.{key}",
                title=f"Assembly: {title} (x{count})",
                description=(
                    f"{why} Found {count} occurrence(s) in the executable code."
                ),
                severity=sev,
                category="disassembly",
                occurrences=count,
            )

        # PEB access can also surface via the instruction classifier.
        if cat_counts.get("peb") and "peb_x64" not in sig_hits and "peb_x86" not in sig_hits:
            result.add(
                id="disasm.peb_access",
                title="Assembly: PEB access near entry point",
                description=(
                    "Instructions near the entry point read the Process "
                    "Environment Block — a technique shellcode uses to find loaded "
                    "modules and resolve API addresses without imports."
                ),
                severity=Severity.HIGH,
                category="disassembly",
            )

        syscalls = cat_counts.get("syscall", 0)
        if syscalls:
            # Direct syscalls are very suspicious in a Windows PE, but common in
            # statically-linked Linux/Go binaries, so keep the weight modest.
            result.add(
                id="disasm.direct_syscall",
                title=f"Assembly: direct syscall/sysenter ({syscalls} near entry)",
                description=(
                    "The code issues direct system calls instead of going through "
                    "the normal library functions. Malware uses direct syscalls to "
                    "bypass user-mode API hooks placed by security products."
                ),
                severity=Severity.LOW,
                category="disassembly",
                count=syscalls,
            )

        anti = cat_counts.get("anti-analysis", 0)
        if anti >= 2:
            result.add(
                id="disasm.anti_analysis",
                title=f"Assembly: anti-analysis instructions ({anti})",
                description=(
                    "Timing (RDTSC) and/or CPU-probing (CPUID) instructions appear "
                    "near the entry point. These are frequently used to detect "
                    "debuggers, sandboxes and virtual machines."
                ),
                severity=Severity.LOW,
                category="disassembly",
                count=anti,
            )

        if cat_counts.get("anti-debug"):
            result.add(
                id="disasm.anti_debug",
                title="Assembly: anti-debug interrupt",
                description=(
                    "An INT3 / INT 0x2d interrupt instruction was found in the code "
                    "stream — a common anti-debugging trap."
                ),
                severity=Severity.MEDIUM,
                category="disassembly",
            )

        if cat_counts.get("stack-pivot"):
            pivot_desc = (
                "A stack-pivot instruction (e.g. moving a register into ESP/RSP) "
                "was found. Stack pivots are a building block of ROP-based "
                "exploitation and shellcode."
            )
            pivot_sev = Severity.LOW
            if _downweight:
                pivot_sev = Severity.INFO
                pivot_desc += (
                    f" (Informational: this is a {runtime} binary, whose runtime "
                    "legitimately switches stacks at startup.)"
                )
            result.add(
                id="disasm.stack_pivot",
                title="Assembly: stack pivot",
                description=pivot_desc,
                severity=pivot_sev,
                category="disassembly",
            )

    # ------------------------------------------------------------------ #
    def _load(self, ctx: FileContext):
        """Return (code_bytes, entry_va, archkey, exec_section_bytes)."""
        if ctx.data[:2] == b"MZ" and _HAVE_PEFILE:
            return self._load_pe(ctx.data)
        if ctx.data[:4] == b"\x7fELF" and _HAVE_ELF:
            return self._load_elf(ctx.data)
        return None

    @staticmethod
    def _load_pe(data: bytes):
        pe = pefile.PE(data=data, fast_load=True)
        machine = pe.FILE_HEADER.Machine
        archkey = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64",
                   0x1C0: "arm", 0x1C4: "arm"}.get(machine)
        if archkey is None:
            pe.close()
            return None
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        code = b""
        exec_bytes = b""
        for section in pe.sections:
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                exec_bytes += section.get_data()[: 2 * 1024 * 1024]
            if section.contains_rva(ep_rva):
                off = section.get_offset_from_rva(ep_rva)
                code = data[off: off + _WINDOW_BYTES]
        entry_va = image_base + ep_rva
        pe.close()
        return code, entry_va, archkey, exec_bytes or code

    @staticmethod
    def _load_elf(data: bytes):
        elf = ELFFile(io.BytesIO(data))
        archmap = {"x86": "x86", "x64": "x86_64", "ARM": "arm", "AArch64": "arm64"}
        archkey = archmap.get(elf.get_machine_arch())
        if archkey is None:
            return None
        entry = elf["e_entry"]
        code = b""
        exec_bytes = b""
        for section in elf.iter_sections():
            flags = section["sh_flags"]
            addr = section["sh_addr"]
            size = section["sh_size"]
            if flags & 0x4 and section["sh_type"] == "SHT_PROGBITS":  # SHF_EXECINSTR
                exec_bytes += section.data()[: 2 * 1024 * 1024]
                if addr <= entry < addr + size:
                    start = section["sh_offset"] + (entry - addr)
                    code = data[start: start + _WINDOW_BYTES]
        return code, entry, archkey, exec_bytes or code

    @staticmethod
    def _capstone_for(archkey: str):
        if not _HAVE_CAPSTONE:
            return None
        mapping = {
            "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }
        spec = mapping.get(archkey)
        if not spec:
            return None
        return capstone.Cs(*spec)


def _classify_instruction(mnemonic: str, op_str: str):
    """Return (category, severity_label, note) for a suspicious instruction."""
    m = mnemonic.lower()
    op = op_str.lower()

    if "fs:[0x30]" in op or "gs:[0x60]" in op:
        return ("peb", "high", "Reads the PEB to locate modules / resolve APIs.")
    if m in ("syscall", "sysenter"):
        return ("syscall", "low", "Direct system call (bypasses API hooks).")
    if m in ("rdtsc", "rdtscp", "cpuid"):
        return ("anti-analysis", "low", "Timing / VM-probe instruction (evasion).")
    if m == "int":
        if op.strip() in ("3", "0x3", "0x2d"):
            return ("anti-debug", "medium", "Anti-debug interrupt.")
        if op.strip() in ("0x80", "0x2e"):
            return ("syscall", "low", "Interrupt-based system call.")
    if m in ("call", "jmp"):
        target = op.strip()
        if target in _REGS or target.startswith(("qword ptr [", "dword ptr [")):
            return ("indirect", "info", "Indirect (computed) control-flow transfer.")
    if m in ("mov", "xchg") and ("esp" in op.split(",")[0] or "rsp" in op.split(",")[0]):
        # Writing a register into the stack pointer = stack pivot (not push/pop).
        parts = [p.strip() for p in op.split(",")]
        if len(parts) == 2 and parts[1] in _REGS:
            return ("stack-pivot", "low", "Stack pivot (ROP / shellcode).")
    return None
