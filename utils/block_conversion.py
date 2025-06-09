from typing import List


def text_to_blocks(text: str, block_size: int = 16) -> List[int]:
    """
    Converts input text into integer blocks of a specified size.

    :param text: Input string to be converted into blocks.
    :param block_size: Size of each block in bytes (default = 16 bytes).
    :return: List of integer blocks.
    """
    text_bytes = text.encode('utf-8')
    # Pad text with spaces to make its size a multiple of block_size
    while len(text_bytes) % block_size != 0:
        text_bytes += b' '
    # Split into blocks of block_size and convert to integers
    blocks = [int.from_bytes(text_bytes[i:i + block_size], 'big') for i in range(0, len(text_bytes), block_size)]
    print(f"text_to_blocks: input={text}, blocks={blocks}")
    return blocks


def blocks_to_text(blocks: List[int], block_size: int = 16) -> str:
    """
    Converts a list of integer blocks back into a string.

    :param blocks: List of integer blocks to be converted.
    :param block_size: Size of each block in bytes (default = 16 bytes).
    :return: Decoded string.
    """
    print(f"blocks_to_text: input blocks={blocks}")
    # Convert each integer block back to bytes and concatenate
    raw = b''.join(b.to_bytes(block_size, 'big') for b in blocks)
    # Strip padding spaces and decode
    return raw.rstrip(b' ').decode('utf-8')
