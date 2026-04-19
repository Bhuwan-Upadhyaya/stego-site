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
    filename_bytes = secret_filename.encode("utf-8")

    payload = bytearray()
    payload += MAGIC
    payload += struct.pack(">I", len(secret_data))
    payload += struct.pack(">H", len(filename_bytes))
    payload += filename_bytes
    payload += secret_data

    return bytes(payload)


def parse_payload(payload: bytes):
    if len(payload) < 10:
        raise ValueError("Payload too short")

    if payload[:4] != MAGIC:
        raise ValueError("Invalid payload header")

    data_len = struct.unpack(">I", payload[4:8])[0]
    name_len = struct.unpack(">H", payload[8:10])[0]

    filename = payload[10:10 + name_len].decode("utf-8")
    data = payload[10 + name_len:10 + name_len + data_len]

    return filename, data


def interval_generator(base_l: int, mode: str):
    if base_l <= 0:
        raise ValueError("L must be greater than 0")

    if mode == "fixed":
        while True:
            yield base_l

    elif mode == "alternate":
        pattern = [base_l, base_l * 2, base_l + 20]
        i = 0
        while True:
            yield pattern[i % len(pattern)]
            i += 1

    elif mode == "increasing":
        step = 0
        while True:
            yield base_l + (step % 4) * 2
            step += 1

    else:
        raise ValueError("Unsupported mode")


# ======================
# SAFE EMBEDDING
# ======================
def embed_message(carrier_bytes: bytes, secret_bytes: bytes, secret_filename: str,
                  start_bit: int, l_value: int, mode: str):

    payload = build_payload(secret_bytes, secret_filename)
    payload_bits = bytes_to_bits(payload)

    carrier = bytearray(carrier_bytes)

    # skip header region
    SAFE_START = max(start_bit, 4096)  # 4096 bits = 512 bytes
    byte_index = SAFE_START // 8

    gaps = interval_generator(l_value, mode)

    for bit in payload_bits:
        if byte_index >= len(carrier):
            raise ValueError("Carrier too small")

        # ONLY LSB modification
        carrier[byte_index] = (carrier[byte_index] & 0b11111110) | bit

        step = max(1, next(gaps) // 8)
        byte_index += step

    return bytes(carrier)


# ======================
# SAFE EXTRACTION
# ======================
def extract_message(stego_bytes: bytes, start_bit: int, l_value: int, mode: str, max_payload_bytes: int = 10_000_000):

    carrier = stego_bytes

    SAFE_START = max(start_bit, 4096)
    byte_index = SAFE_START // 8

    gaps = interval_generator(l_value, mode)

    bits = []

    for _ in range(max_payload_bytes * 8):
        if byte_index >= len(carrier):
            break

        bits.append(carrier[byte_index] & 1)

        step = max(1, next(gaps) // 8)
        byte_index += step

    payload_bytes = bits_to_bytes(bits)

    return parse_payload(payload_bytes)


# ======================
# TEST
# ======================
if __name__ == "__main__":
    print("Running test...")

    carrier = bytes([0xAA] * 8000)
    secret = b"Hello Bhuwan, this works!"
    name = "secret.txt"

    S = 1024
    L = 8
    mode = "fixed"

    stego = embed_message(carrier, secret, name, S, L, mode)
    fname, data = extract_message(stego, S, L, mode)

    print("Recovered:", fname)
    print(data.decode())
    print("Test passed.")