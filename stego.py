import struct

MAGIC = b"STEG"


def bytes_to_bits(data: bytes):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError("Bit length must be a multiple of 8")

    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def build_payload(secret_data: bytes, secret_filename: str):
    """
    Payload format:
    [MAGIC:4 bytes][DATA_LEN:4 bytes][NAME_LEN:2 bytes][FILENAME][DATA]
    """
    filename_bytes = secret_filename.encode("utf-8")

    payload = bytearray()
    payload += MAGIC
    payload += struct.pack(">I", len(secret_data))
    payload += struct.pack(">H", len(filename_bytes))
    payload += filename_bytes
    payload += secret_data

    return bytes(payload)


def parse_payload(payload: bytes):
    if payload[:4] != MAGIC:
        raise ValueError("Invalid payload header")

    data_len = struct.unpack(">I", payload[4:8])[0]
    name_len = struct.unpack(">H", payload[8:10])[0]

    filename_start = 10
    filename_end = filename_start + name_len
    data_start = filename_end
    data_end = data_start + data_len

    filename = payload[filename_start:filename_end].decode("utf-8")
    secret_data = payload[data_start:data_end]

    return filename, secret_data


def interval_generator(base_l: int, mode: str):
    """
    mode choices:
    - fixed
    - alternate
    - increasing
    """
    if base_l <= 0:
        raise ValueError("L must be greater than 0")

    if mode == "fixed":
        while True:
            yield base_l

    elif mode == "alternate":
        pattern = [base_l, base_l * 2, base_l + 20]
        idx = 0
        while True:
            yield pattern[idx % len(pattern)]
            idx += 1

    elif mode == "increasing":
        step = 0
        while True:
            yield base_l + (step % 4) * 2
            step += 1

    else:
        raise ValueError("Unsupported mode")


def embedding_positions(total_bits: int, start_bit: int, base_l: int, mode: str, count_needed: int):
    if start_bit < 0:
        raise ValueError("S must be non-negative")

    positions = []
    pos = start_bit
    gaps = interval_generator(base_l, mode)

    while pos < total_bits and len(positions) < count_needed:
        positions.append(pos)
        pos += next(gaps)

    return positions


def capacity_bits(total_bits: int, start_bit: int, base_l: int):
    """
    Approximate capacity for fixed mode.
    """
    if base_l <= 0:
        raise ValueError("L must be greater than 0")
    if start_bit >= total_bits:
        return 0
    return ((total_bits - 1 - start_bit) // base_l) + 1


def embed_message(carrier_bytes: bytes, secret_bytes: bytes, secret_filename: str,
                  start_bit: int, l_value: int, mode: str):
    carrier_bits = bytes_to_bits(carrier_bytes)
    payload = build_payload(secret_bytes, secret_filename)
    payload_bits = bytes_to_bits(payload)

    positions = embedding_positions(
        total_bits=len(carrier_bits),
        start_bit=start_bit,
        base_l=l_value,
        mode=mode,
        count_needed=len(payload_bits)
    )

    if len(positions) < len(payload_bits):
        raise ValueError("Carrier file is too small for this message and parameter choice")

    for pos, bit in zip(positions, payload_bits):
        carrier_bits[pos] = bit

    return bits_to_bytes(carrier_bits)


def extract_message(stego_bytes: bytes, start_bit: int, l_value: int, mode: str, max_payload_bytes: int = 10_000_000):
    stego_bits = bytes_to_bits(stego_bytes)

    # Read header first: MAGIC(4) + DATA_LEN(4) + NAME_LEN(2) = 10 bytes = 80 bits
    header_bytes_len = 10
    header_bits_len = header_bytes_len * 8

    header_positions = embedding_positions(
        total_bits=len(stego_bits),
        start_bit=start_bit,
        base_l=l_value,
        mode=mode,
        count_needed=header_bits_len
    )

    if len(header_positions) < header_bits_len:
        raise ValueError("Not enough bits to extract header")

    header_bits = [stego_bits[pos] for pos in header_positions]
    header_bytes = bits_to_bytes(header_bits)

    if header_bytes[:4] != MAGIC:
        raise ValueError("No valid hidden payload found")

    data_len = struct.unpack(">I", header_bytes[4:8])[0]
    name_len = struct.unpack(">H", header_bytes[8:10])[0]

    total_payload_len = 4 + 4 + 2 + name_len + data_len

    if total_payload_len > max_payload_bytes:
        raise ValueError("Payload too large or invalid")

    total_payload_bits = total_payload_len * 8

    all_positions = embedding_positions(
        total_bits=len(stego_bits),
        start_bit=start_bit,
        base_l=l_value,
        mode=mode,
        count_needed=total_payload_bits
    )

    if len(all_positions) < total_payload_bits:
        raise ValueError("Carrier does not contain complete payload")

    payload_bits = [stego_bits[pos] for pos in all_positions]
    payload_bytes = bits_to_bytes(payload_bits)

    return parse_payload(payload_bytes)


if __name__ == "__main__":
    print("Running simple self-test...")

    carrier = bytes([0] * 2000)  # 2000 bytes carrier
    secret = b"Hello Bhuwan, this is a hidden message!"
    secret_name = "secret.txt"

    start_bit = 128
    l_value = 8
    mode = "fixed"

    stego = embed_message(carrier, secret, secret_name, start_bit, l_value, mode)
    recovered_name, recovered_data = extract_message(stego, start_bit, l_value, mode)

    print("Recovered filename:", recovered_name)
    print("Recovered message:", recovered_data.decode("utf-8"))
    print("Self-test passed.")