from typing import List

def text_to_blocks(text: str) -> List[int]:
    text_bytes = text.encode('utf-8')
    while len(text_bytes) % 8 != 0:
        text_bytes += b' '
    return [int.from_bytes(text_bytes[i:i+8], 'big') for i in range(0, len(text_bytes), 8)]

def blocks_to_text(blocks: List[int]) -> str:
    raw = b''.join(b.to_bytes(8, 'big') for b in blocks)
    return raw.rstrip(b' ').decode('utf-8')