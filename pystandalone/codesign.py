# Vibed alternative for cross-platform `codesign` functionality
# To be replaced in the future with some artisanal dissect.executable code
from __future__ import annotations

import hashlib
import struct

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_SWAPPED = 0xBEBAFECA

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D

# Code signature constants (all big-endian in the blob)
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSSLOT_CODEDIRECTORY = 0

CS_ADHOC = 0x2
CS_LINKER_SIGNED = 0x20000
CS_EXECSEG_MAIN_BINARY = 0x1
CS_HASHTYPE_SHA256 = 2
CS_HASH_SIZE = 32
CS_PAGE_SIZE_LOG2 = 12
CS_PAGE_SIZE = 1 << CS_PAGE_SIZE_LOG2

# CodeDirectory version
CS_CODEDIRECTORY_VERSION = 0x20400

# Mach-O 64-bit header size
MACHO_HEADER_SIZE = 32

# LC_SEGMENT_64 command size
LC_SEGMENT_64_SIZE = 72

# LC_CODE_SIGNATURE command size
LC_CODE_SIGNATURE_SIZE = 16

# Fat arch entry size
FAT_ARCH_SIZE = 20
FAT_HEADER_SIZE = 8

# Fat binary slice alignment (2^14 = 16384)
FAT_ALIGN = 14


def adhoc_sign(data: bytes) -> bytes:
    """Ad-hoc sign a Mach-O binary (thin or fat)."""
    if len(data) < 4:
        return data

    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_SWAPPED):
        return _sign_fat(data)

    magic_le = struct.unpack("<I", data[:4])[0]
    if magic_le == MH_MAGIC_64:
        return _sign_thin(bytearray(data))

    return data


def _sign_fat(data: bytes) -> bytes:
    """Sign each slice of a fat Mach-O binary."""
    _, nfat_arch = struct.unpack(">II", data[:FAT_HEADER_SIZE])

    slices: list[tuple[int, int, int, bytes]] = []
    for i in range(nfat_arch):
        entry_offset = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE
        cputype, cpusubtype, offset, size, align = struct.unpack(
            ">IIIiI", data[entry_offset : entry_offset + FAT_ARCH_SIZE]
        )
        slice_data = data[offset : offset + size]
        signed = _sign_thin(bytearray(slice_data))
        slices.append((cputype, cpusubtype, align, signed))

    return _assemble_fat(slices)


def _assemble_fat(slices: list[tuple[int, int, int, bytes]]) -> bytes:
    """Reassemble a fat binary from individually signed slices."""
    header_size = FAT_HEADER_SIZE + len(slices) * FAT_ARCH_SIZE
    buf = bytearray()
    buf += struct.pack(">II", FAT_MAGIC, len(slices))

    # Calculate offsets with proper alignment
    offset = header_size
    offsets = []
    for _, _, align, slice_data in slices:
        alignment = 1 << align
        offset = (offset + alignment - 1) & ~(alignment - 1)
        offsets.append(offset)
        offset += len(slice_data)

    # Write fat arch entries
    for (cputype, cpusubtype, align, slice_data), off in zip(slices, offsets, strict=False):
        buf += struct.pack(">IIIiI", cputype, cpusubtype, off, len(slice_data), align)

    # Write slices at their offsets
    for (_, _, _, slice_data), off in zip(slices, offsets, strict=False):
        if len(buf) < off:
            buf += b"\x00" * (off - len(buf))
        buf += slice_data

    return bytes(buf)


def _sign_thin(data: bytearray) -> bytes:
    """Ad-hoc sign a thin (single-architecture) 64-bit Mach-O binary."""
    # Parse Mach-O header (little-endian)
    magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack("<IiiIIIII", data[:MACHO_HEADER_SIZE])
    if magic != MH_MAGIC_64:
        return bytes(data)

    # Walk load commands
    text_fileoff = 0
    text_filesize = 0
    linkedit_cmd_offset = 0
    linkedit_fileoff = 0
    linkedit_filesize = 0
    codesig_cmd_offset = 0
    codesig_dataoff = 0

    offset = MACHO_HEADER_SIZE
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[offset : offset + 8])

        if cmd == LC_SEGMENT_64:
            segname = data[offset + 8 : offset + 24].split(b"\x00", 1)[0].decode()
            # LC_SEGMENT_64: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) ...
            seg_fileoff, seg_filesize = struct.unpack("<QQ", data[offset + 40 : offset + 56])

            if segname == "__TEXT":
                text_fileoff = seg_fileoff
                text_filesize = seg_filesize
            elif segname == "__LINKEDIT":
                linkedit_cmd_offset = offset
                linkedit_fileoff = seg_fileoff
                linkedit_filesize = seg_filesize

        elif cmd == LC_CODE_SIGNATURE:
            codesig_cmd_offset = offset
            codesig_dataoff = struct.unpack("<I", data[offset + 8 : offset + 12])[0]

        offset += cmdsize

    # Strip existing code signature if present
    if codesig_cmd_offset:
        # Truncate data at signature offset
        data = data[:codesig_dataoff]

        # Shrink __LINKEDIT to not include the old signature
        linkedit_filesize = codesig_dataoff - linkedit_fileoff

        # Zero out the LC_CODE_SIGNATURE load command
        data[codesig_cmd_offset : codesig_cmd_offset + LC_CODE_SIGNATURE_SIZE] = b"\x00" * LC_CODE_SIGNATURE_SIZE

        # Update header: decrement ncmds and sizeofcmds
        ncmds -= 1
        sizeofcmds -= LC_CODE_SIGNATURE_SIZE
        struct.pack_into("<II", data, 16, ncmds, sizeofcmds)

    code_size = len(data)

    # Pad code to 16-byte alignment before appending signature
    code_pad = _align_up(code_size, 16) - code_size
    if code_pad:
        data += b"\x00" * code_pad
        code_size = len(data)
        # Update __LINKEDIT filesize to include padding
        if linkedit_cmd_offset:
            linkedit_filesize += code_pad

    # Calculate the signature blob size so we can write the load command first
    nhashes = (code_size + CS_PAGE_SIZE - 1) // CS_PAGE_SIZE
    # SuperBlob(12) + BlobIndex(8) + CodeDirectory(88) + ident(1) + hashes
    sig_blob_size = 12 + 8 + 88 + 1 + nhashes * CS_HASH_SIZE
    # Pad to 16-byte alignment
    sig_blob_size = _align_up(sig_blob_size, 16)

    # Write LC_CODE_SIGNATURE load command into slack space after existing load commands
    lc_offset = MACHO_HEADER_SIZE + sizeofcmds
    struct.pack_into("<IIII", data, lc_offset, LC_CODE_SIGNATURE, LC_CODE_SIGNATURE_SIZE, code_size, sig_blob_size)

    # Update header: increment ncmds and sizeofcmds
    ncmds += 1
    sizeofcmds += LC_CODE_SIGNATURE_SIZE
    struct.pack_into("<II", data, 16, ncmds, sizeofcmds)

    # Update __LINKEDIT segment to cover the signature
    if linkedit_cmd_offset:
        new_linkedit_filesize = linkedit_filesize + sig_blob_size
        new_linkedit_vmsize = _align_up(new_linkedit_filesize, CS_PAGE_SIZE)
        # LC_SEGMENT_64: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) ...
        struct.pack_into("<Q", data, linkedit_cmd_offset + 32, new_linkedit_vmsize)
        struct.pack_into("<Q", data, linkedit_cmd_offset + 48, new_linkedit_filesize)

    # Compute page hashes over the final binary content (before appending the signature)
    page_hashes = _compute_page_hashes(data, code_size)

    # Build the signature blob with hashes
    sig_blob = _build_code_signature(code_size, text_fileoff, text_filesize, page_hashes)

    # Pad to 16-byte alignment
    pad_size = sig_blob_size - len(sig_blob)
    if pad_size > 0:
        sig_blob += b"\x00" * pad_size

    # Append signature blob
    data += sig_blob

    return bytes(data)


def _build_code_signature(
    code_size: int,
    exec_seg_base: int,
    exec_seg_limit: int,
    page_hashes: list[bytes],
) -> bytes:
    """Build a complete ad-hoc code signature SuperBlob with page hashes."""
    nhashes = len(page_hashes)

    ident = b"\x00"
    ident_offset = 88
    hash_offset = ident_offset + len(ident)
    cd_length = hash_offset + nhashes * CS_HASH_SIZE
    total_length = 12 + 8 + cd_length

    buf = bytearray()

    # SuperBlob header (big-endian)
    buf += struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, total_length, 1)

    # BlobIndex entry (big-endian)
    buf += struct.pack(">II", CSSLOT_CODEDIRECTORY, 20)

    # CodeDirectory (big-endian)
    buf += struct.pack(">II", CSMAGIC_CODEDIRECTORY, cd_length)
    buf += struct.pack(">I", CS_CODEDIRECTORY_VERSION)
    buf += struct.pack(">I", CS_ADHOC)
    buf += struct.pack(">I", hash_offset)
    buf += struct.pack(">I", ident_offset)
    buf += struct.pack(">I", 0)  # nSpecialSlots
    buf += struct.pack(">I", nhashes)  # nCodeSlots
    buf += struct.pack(">I", code_size)  # codeLimit
    buf += struct.pack(">B", CS_HASH_SIZE)
    buf += struct.pack(">B", CS_HASHTYPE_SHA256)
    buf += struct.pack(">B", 0)  # platform
    buf += struct.pack(">B", CS_PAGE_SIZE_LOG2)
    buf += struct.pack(">I", 0)  # spare2
    buf += struct.pack(">I", 0)  # scatterOffset
    buf += struct.pack(">I", 0)  # teamOffset
    buf += struct.pack(">I", 0)  # spare3
    buf += struct.pack(">Q", code_size)  # codeLimit64
    buf += struct.pack(">Q", exec_seg_base)
    buf += struct.pack(">Q", exec_seg_limit)
    buf += struct.pack(">Q", CS_EXECSEG_MAIN_BINARY)

    # Identifier
    buf += ident

    # Page hashes
    for h in page_hashes:
        buf += h

    return bytes(buf)


def _compute_page_hashes(data: bytes, code_size: int) -> list[bytes]:
    """Compute SHA-256 hashes for each page of the binary."""
    hashes = []
    for i in range(0, code_size, CS_PAGE_SIZE):
        page = data[i : i + CS_PAGE_SIZE]
        hashes.append(hashlib.sha256(page).digest())
    return hashes


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)
