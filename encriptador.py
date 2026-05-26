import sys

def xor_with_moving_key(data, key):
    # XOR donde la clave cambia en cada paso (más difícil de analizar)
    output = bytearray()
    for i in range(len(data)):
        output.append(data[i] ^ key[i % len(key)] ^ (i & 0xFF))
    return output

def to_ipv4_list(data):
    # Rellenamos con ceros para que sea múltiplo de 4
    while len(data) % 4 != 0:
        data.append(0)

    ips = []
    for i in range(0, len(data), 4):
        ip = f"{data[i]}.{data[i+1]}.{data[i+2]}.{data[i+3]}"
        ips.append(f'"{ip}"')
    return ips

def main():
    if len(sys.argv) < 2: return

    with open(sys.argv[1], "rb") as f:
        payload = bytearray(f.read())

    key = b"ASFASFASFASFDVGSVBCBCXCBXCBNKDJBJADFBAJBSFKJABANKFCAKC"

    # 1. Cifrado dinámico
    encrypted_data = xor_with_moving_key(payload, key)

    # 2. Conversión a formato de "Lista de IPs"
    ip_list = to_ipv4_list(encrypted_data)

    print("char* shell_ips[] = {")
    print(",\n".join(ip_list))
    print("};")
    print(f"\nint shell_ips_count = {len(ip_list)};")

if __name__ == "__main__":
    main()