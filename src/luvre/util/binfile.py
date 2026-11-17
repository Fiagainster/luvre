"""File-level triage without any dependency: type sniff, hashes, entropy,
section tables and overlay (appended data) detection for PE and ELF.

Everything here works on raw bytes so it is trivially testable.
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------- hashes

def file_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


# -------------------------------------------------------------------- entropy

def shannon_entropy(data: bytes) -> float:
    """Bits per byte (0..8) for the whole buffer."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def entropy_profile(data: bytes, chunks: int = 64) -> list[float]:
    """Entropy of `chunks` equal-size slices, for the packed-ness sparkline."""
    if not data:
        return []
    size = max(1, len(data) // chunks)
    out = []
    for i in range(0, len(data), size):
        out.append(shannon_entropy(data[i : i + size]))
        if len(out) >= chunks:
            break
    return out


# ------------------------------------------------------------------ type sniff

def sniff_format(data: bytes) -> dict[str, Any]:
    """Coarse container sniff — Ghidra does the real loading later."""
    if data.startswith(b"MZ"):
        return {"format": "PE", "detail": "Windows executable (MZ)"}
    if data.startswith(b"\x7fELF"):
        bits = {1: "32-bit", 2: "64-bit"}.get(data[4], f"class{data[4]}")
        endi = {1: "LSB", 2: "MSB"}.get(data[5], "?")
        return {"format": "ELF", "detail": f"ELF {bits} {endi}"}
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return {"format": "MachO", "detail": "macOS Mach-O"}
    if data.startswith(b"!<arch>\n"):
        return {"format": "AR", "detail": "ar archive (member files inside, use `ar x`)"}
    if data.startswith(b"PK\x03\x04"):
        return {"format": "ZIP", "detail": "zip archive"}
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return {"format": "7z", "detail": "7-zip archive"}
    if data.startswith(b"\x1f\x8b"):
        return {"format": "GZIP", "detail": "gzip stream"}
    if data.startswith(b"UPX!"):
        return {"format": "UPX", "detail": "UPX packed (magic at head)"}
    return {"format": "RAW", "detail": "unrecognized header"}


# --------------------------------------------------------------- overlay (PE)

_MACHINE_NAMES = {
    0x014C: "i386",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x01C4: "ARMNT",
}


def parse_pe(data: bytes) -> dict[str, Any] | None:
    """Minimal PE parser: sections, machine, overlay offset. None if not PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return None
        machine, nsec, _ts, sym_ptr, nsym, opt_size, chars = struct.unpack_from(
            "<HHIIIHH", data, pe_off + 4
        )
        opt_off = pe_off + 24
        if opt_off + opt_size > len(data):
            return None
        magic = struct.unpack_from("<H", data, opt_off)[0] if opt_size else 0
        bits = {0x10B: 32, 0x20B: 64}.get(magic, 0)

        # Certificate table (data directory index 4) sits at the tail too.
        dd_off = opt_off + (0x70 if bits == 64 else 0x60)
        cert_end = 0
        if bits and dd_off + 8 * 5 <= opt_off + opt_size:
            cert_rva, cert_size = struct.unpack_from("<II", data, dd_off + 8 * 4)
            if cert_size:
                cert_end = cert_rva + cert_size  # file offset for this directory

        sections = []
        end_max = 0
        sh_off = opt_off + opt_size
        image_base = 0
        if bits == 64:
            image_base = struct.unpack_from("<Q", data, opt_off + 24)[0] if opt_off + 32 <= len(data) else 0
        elif bits == 32:
            image_base = struct.unpack_from("<I", data, opt_off + 28)[0] if opt_off + 32 <= len(data) else 0
        for i in range(min(nsec, 96)):
            off = sh_off + i * 40
            if off + 40 > len(data):
                break
            raw = data[off : off + 40]
            name = raw[:8].rstrip(b"\x00").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, 8)
            sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "raw_size": rawsize,
                "raw_offset": rawptr,
                "entropy": shannon_entropy(data[rawptr : rawptr + min(rawsize, 1 << 20)]) if rawsize else 0.0,
            })
            end_max = max(end_max, rawptr + rawsize)
        end_max = max(end_max, cert_end)
        # COFF symbol table + string table trail the sections in MinGW/debug
        # builds. They are file structure, not appended payload — counting
        # them as overlay made every debug-built crackme look "packed".
        sym_end = 0
        if sym_ptr and nsym and end_max <= sym_ptr < len(data):
            strtab_off = sym_ptr + 20 * nsym
            if strtab_off + 4 <= len(data):
                strtab_size = struct.unpack_from("<I", data, strtab_off)[0]
                sym_end = min(strtab_off + strtab_size, len(data))
        end_max = max(end_max, sym_end)
        file_len = len(data)
        overlay = file_len - end_max if file_len > end_max else 0
        return {
            "format": "PE",
            "bits": bits,
            "machine": _MACHINE_NAMES.get(machine, f"0x{machine:04x}"),
            "characteristics": chars,
            "image_base": image_base,
            "nsections": nsec,
            "sections": sections,
            "overlay_offset": end_max if overlay else None,
            "overlay_size": overlay,
            "signed": cert_end > 0,
            "coff_symbols": nsym if (sym_ptr and nsym) else 0,
        }
    except struct.error:
        return None


# -------------------------------------------------------------- overlay (ELF)

_ELF_MACHINE = {
    3: "x86",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    8: "MIPS",
    20: "PowerPC",
    243: "RISC-V",
}


def parse_elf(data: bytes) -> dict[str, Any] | None:
    """Minimal ELF parser: machine, endianness, sections, overlay offset."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    try:
        ei_class, ei_data = data[4], data[5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            return None
        is64 = ei_class == 2
        end = "<" if ei_data == 1 else ">"

        if is64:
            e_type, e_machine = struct.unpack_from(f"{end}HH", data, 16)
            e_shoff = struct.unpack_from(f"{end}Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{end}HHH", data, 0x3A)
        else:
            e_type, e_machine = struct.unpack_from(f"{end}HH", data, 16)
            e_shoff = struct.unpack_from(f"{end}I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{end}HHH", data, 0x2E)

        # section headers first (names resolved right after from .shstrtab —
        # without it the triage panel showed numbered sections and "undefined")
        raw_secs = []
        end_max = 0
        for i in range(min(e_shnum, 128)):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(data) or off + 32 > len(data):
                break
            if is64:
                name_off, s_type, _flags, s_addr, offset, size = struct.unpack_from(
                    f"{end}IIQQQQ", data, off
                )
            else:
                name_off, s_type, _flags, s_addr, offset, size = struct.unpack_from(
                    f"{end}IIIIII", data, off
                )
            raw_secs.append((i, name_off, s_type, offset, size, s_addr))
            if s_type != 8:  # SHT_NOBITS
                end_max = max(end_max, offset + size)
        end_max = max(end_max, e_shoff + e_shnum * e_shentsize if e_shnum else 0)

        # resolve names from the string-table section (e_shstrndx; fall back
        # to the first SHT_STRTAB) — hand-crafted ELFs sometimes lie about
        # e_shstrndx (e.g. leaving 0), so require the candidate to actually
        # be a SHT_STRTAB
        names: dict[int, str] = {}
        strsec = None
        if 0 <= e_shstrndx < len(raw_secs) and raw_secs[e_shstrndx][2] == 3:
            strsec = raw_secs[e_shstrndx]
        if strsec is None:
            strsec = next((s for s in raw_secs if s[2] == 3), None)
        if strsec is not None:
            _i, _no, stype, soff, ssize, _sa = strsec
            tab = data[soff : soff + ssize]
            if tab:
                for i, name_off, _t, _o, _s, _a in raw_secs:
                    if 0 <= name_off < len(tab):
                        nul = tab.find(b"\x00", name_off)
                        nm = tab[name_off : nul if nul >= 0 else len(tab)]
                        names[i] = nm.decode("latin1", "replace")

        sections = []
        for i, name_off, s_type, offset, size, s_addr in raw_secs:
            sections.append({
                "index": i,
                "name": names.get(i, ""),
                "type": s_type,
                "addr": s_addr,
                "offset": offset,
                "size": size,
                "entropy": shannon_entropy(data[offset : offset + min(size, 1 << 20)]) if size else 0.0,
            })
        overlay = len(data) - end_max if len(data) > end_max > 0 else 0
        return {
            "format": "ELF",
            "bits": 64 if is64 else 32,
            "endian": "little" if ei_data == 1 else "big",
            "machine": _ELF_MACHINE.get(e_machine, f"0x{e_machine:x}"),
            "type": {2: "EXEC", 3: "DYN", 4: "CORE", 1: "REL"}.get(e_type, str(e_type)),
            "nsections": e_shnum,
            "sections": sections,
            "overlay_offset": end_max if overlay else None,
            "overlay_size": overlay,
        }
    except struct.error:
        return None


# ------------------------------------------------------------------ composite

def triage(data: bytes) -> dict[str, Any]:
    """One-shot file triage: hashes, sniff, sections, overlay, entropy."""
    info: dict[str, Any] = {
        "hashes": file_hashes(data),
        "sniff": sniff_format(data),
        "global_entropy": shannon_entropy(data[: 1 << 22]),
        "entropy_profile": entropy_profile(data[: 1 << 22]),
    }
    parsed = parse_pe(data) or parse_elf(data)
    if parsed:
        info.update(parsed)
        info["overlay_present"] = bool(parsed["overlay_size"])
        sec_ents = [s.get("entropy", 0.0) for s in parsed.get("sections", [])]
        info["max_entropy"] = round(max(sec_ents), 3) if sec_ents else info["global_entropy"]
    else:
        info["sections"] = []
        info["overlay_size"] = max(0, len(data) - 0)
        info["overlay_present"] = False
    return info


# ------------------------------------------------- vaddr → file offset (patch)

def vaddr_to_file_offset(info: dict[str, Any], vaddr: int) -> int | None:
    """Map a STATIC virtual address onto a file offset via the section table.

    Works on the dict from parse_pe / parse_elf.  Only file-backed extents
    are mapped (PE: raw_size window; ELF: SHT_NOBITS sections are skipped) —
    a debugger memory patch that lands in .bss has no home in the file and
    must be reported unmapped instead of silently corrupting a neighbour.
    """
    if info["format"] == "PE":
        image_base = int(info.get("image_base") or 0)
        rva = vaddr - image_base
        if rva < 0:
            return None
        for s in info.get("sections", []):
            raw_size = int(s.get("raw_size") or 0)
            raw_off = int(s.get("raw_offset") or 0)
            va = int(s.get("virtual_address") or 0)
            if raw_size and va <= rva < va + raw_size:
                return raw_off + (rva - va)
        return None
    if info["format"] == "ELF":
        for s in info.get("sections", []):
            addr = int(s.get("addr") or 0)
            size = int(s.get("size") or 0)
            off = int(s.get("offset") or 0)
            if addr and s.get("type") != 8 and addr <= vaddr < addr + size:
                return off + (vaddr - addr)
        return None
    return None


def apply_patches_to_copy(src: Path, patches: list[dict[str, Any]]) -> dict[str, Any]:
    """Write the sample's bytes with debugger patches applied to a COPY under
    `<sample dir>/_lvr/patched/` — the original on disk is never touched.

    Each patch is {addr: int, bytes: hex-str} with a STATIC virtual address
    (the frontend converts runtime→static for ASLR targets before calling).
    """
    data = bytearray(src.read_bytes())
    info = parse_pe(bytes(data)) or parse_elf(bytes(data))
    if info is None:
        raise ValueError("not a PE/ELF image — cannot map addresses to file offsets")
    applied: list[str] = []
    unmapped: list[str] = []
    for pt in patches:
        addr = int(pt.get("addr", -1))
        try:
            blob = bytes.fromhex(str(pt.get("bytes", "")))
        except ValueError as e:
            raise ValueError(f"bad patch hex for {addr:#x}: {e}") from e
        off = vaddr_to_file_offset(info, addr)
        if off is None or off < 0 or off + len(blob) > len(data):
            unmapped.append(f"0x{addr:x}")
            continue
        data[off : off + len(blob)] = blob
        applied.append(f"0x{addr:x}")
    if not applied:
        raise ValueError("no patch landed on a file-backed region "
                         f"(unmapped: {', '.join(unmapped) or 'all'})")
    outdir = src.parent / "_lvr" / "patched"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"{src.stem}_patched_{int(time.time())}{src.suffix}"
    out.write_bytes(bytes(data))
    return {"path": str(out), "applied": len(applied), "total": len(patches),
            "unmapped": unmapped}
