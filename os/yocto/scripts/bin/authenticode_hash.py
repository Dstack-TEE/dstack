#!/usr/bin/env python3

import argparse
import hashlib


def read_le_u16(data: bytes, offset: int) -> int:
    import struct

    return struct.unpack('<H', data[offset:offset + 2])[0]


def read_le_u32(data: bytes, offset: int) -> int:
    import struct

    return struct.unpack('<I', data[offset:offset + 4])[0]


def authenticode_hash(filepath: str) -> str:
    with open(filepath, 'rb') as f:
        data = f.read()

    # Read DOS header
    lfanew_offset = 0x3C
    lfanew = read_le_u32(data, lfanew_offset)

    # Verify PE signature
    pe_sig_offset = lfanew
    pe_sig = read_le_u32(data, pe_sig_offset)
    IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
    if pe_sig != IMAGE_NT_SIGNATURE:
        raise ValueError(f"Invalid PE signature in {filepath}")

    # Read COFF header
    coff_header_offset = pe_sig_offset + 4
    optional_header_size = read_le_u16(data, coff_header_offset + 16)

    # Read Optional header magic
    optional_header_offset = coff_header_offset + 20
    magic = read_le_u16(data, optional_header_offset)

    is_pe32_plus = (magic == 0x20B)

    # Calculate offsets for excluded regions (checksum and cert directory)
    checksum_offset = optional_header_offset + 64
    checksum_end = checksum_offset + 4

    data_dir_offset = optional_header_offset + (112 if is_pe32_plus else 96)
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    cert_dir_offset = data_dir_offset + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8)
    cert_dir_end = cert_dir_offset + 8

    size_of_headers_offset = optional_header_offset + 60
    size_of_headers = read_le_u32(data, size_of_headers_offset)

    # Hash header (excluding checksum and cert directory)
    hasher = hashlib.sha256()
    hasher.update(data[0:checksum_offset])
    hasher.update(data[checksum_end:cert_dir_offset])
    hasher.update(data[cert_dir_end:size_of_headers])

    sum_of_bytes_hashed = size_of_headers

    # Read section table
    num_sections_offset = coff_header_offset + 2
    num_sections = read_le_u16(data, num_sections_offset)

    section_table_offset = optional_header_offset + optional_header_size
    section_size = 40

    sections = []
    for i in range(num_sections):
        section_offset = section_table_offset + (i * section_size)

        ptr_raw_data_offset = section_offset + 20
        ptr_raw_data = read_le_u32(data, ptr_raw_data_offset)

        size_raw_data_offset = section_offset + 16
        size_raw_data = read_le_u32(data, size_raw_data_offset)

        if size_raw_data > 0:
            sections.append((ptr_raw_data, size_raw_data))

    # Sort sections by offset
    sections.sort(key=lambda x: x[0])

    # Hash sections
    for offset, size in sections:
        start = offset
        end = start + size

        if end <= len(data):
            hasher.update(data[start:end])
        else:
            available_size = max(0, len(data) - start)
            if available_size > 0:
                hasher.update(data[start:start + available_size])

        sum_of_bytes_hashed += size

    file_size = len(data)

    # Read certificate table info
    cert_table_addr = read_le_u32(data, cert_dir_offset)
    cert_table_size = read_le_u32(data, cert_dir_offset + 4)

    # Hash trailing data (excluding certificate table)
    if cert_table_addr > 0 and cert_table_size > 0 and file_size > sum_of_bytes_hashed:
        trailing_data_len = file_size - sum_of_bytes_hashed

        if trailing_data_len > cert_table_size:
            hashed_trailing_len = trailing_data_len - cert_table_size
            trailing_start = sum_of_bytes_hashed

            if trailing_start + hashed_trailing_len <= len(data):
                hasher.update(data[trailing_start:trailing_start + hashed_trailing_len])

    # Add padding to align to 8 bytes
    remainder = file_size % 8
    if remainder != 0:
        padding = bytes([0] * (8 - remainder))
        hasher.update(padding)

    return hasher.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Calculate PE/COFF Authenticode SHA256 hash (TPM Event Log compatible)'
    )
    parser.add_argument('file', help='Path to PE/COFF binary (e.g., UKI .efi)')
    args = parser.parse_args()

    print(authenticode_hash(args.file))


if __name__ == '__main__':
    main()
