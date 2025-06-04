from scapy.all import rdpcap, TCP
from cipher.custom_cipher import CustomCipher
from utils.block_conversion import blocks_to_text
import binascii
import sys

# --- CONFIG ---

# Test key for Alice before rekeying: 94372349846199df
# Test key for Alice after rekeying: 2b02f8b8730e9ce9
# Test key for Bob before rekeying: bebfd237bb082579
# Test key for Bob after rekeying: b584d5f924dae074

PCAP_FILE = "wireshark_chats/chat_logs2.pcap"
SESSION_KEY_HEX = "2b02f8b8730e9ce9"  # Replace with your key

def extract_payloads(pcap_file):
    packets = rdpcap(pcap_file)
    payloads = []

    for pkt in packets:
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            raw = bytes(tcp.payload)
            if raw and len(raw) % 8 == 0:
                payloads.append(raw)
    return payloads

def decrypt_payload(payload, cipher):
    blocks = [int.from_bytes(payload[i:i+8], 'big') for i in range(0, len(payload), 8)]
    try:
        decrypted_blocks = [cipher.decrypt_block(b) for b in blocks]
        return blocks_to_text(decrypted_blocks)
    except Exception as e:
        return f"[DECRYPT FAIL] {e}"

def main():
    print("📂 Reading PCAP...")
    payloads = extract_payloads(PCAP_FILE)
    print(f"✅ Found {len(payloads)} candidate payloads")

    cipher = CustomCipher(key=SESSION_KEY_HEX[:16])  # 16 hex chars = 64 bits

    for i, payload in enumerate(payloads):
        decrypted = decrypt_payload(payload, cipher)
        print(f"\n🧾 Packet {i + 1}")
        print(f"↳ Raw: {binascii.hexlify(payload).decode()}")
        print(f"↳ Decrypted: {decrypted}")

if __name__ == "__main__":
    main()
