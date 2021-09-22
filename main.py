"""MAC Attack, COSC 483, Created by Clark Hathaway"""

import struct
from sha1 import SHA1


def padding_with_k(m: bytes) -> bytes:
    # This was originally in James Seo's SHA implementation (see sha1.py)
    # Moved here so that messages could be padded before the actual data is
    # passed to SHA-1, as we will modify the messages before passing them as
    # an extra block.

    ml = len(m) * 8
    m += b"\x80"
    m += b"\x00" * (-(len(m) + 8) % 64)
    m += struct.pack(">Q", ml)
    return m


def main():
    # HMAC received from the submission site
    hmac = (0xff102e60,
            0x74a0444a,
            0x80cff5d7,
            0x0c700870,
            0x9af8a322)
    # Extra spaces prepended to the original message as they
    # will not be used in SHA, only for ensuring padding and K are computed correctly
    m1 = ' ' * (128 // 8) + "No one has completed Project #3 so give them all a 0."
    m2 = "P.S. Except for Clark Hathaway; give him full marks :)"

    # Compute padding for the original message and the malicious message
    msg1 = padding_with_k(m1.encode())
    msg2 = padding_with_k((msg1 + m2.encode()))

    # Print so we can use these values to submit
    print("Modified message:")
    print((msg1[(128 // 8):] + m2.encode()).hex())
    print("New MAC:")
    print(SHA1(
        msg=msg2[len(msg1):],
        iv=hmac
    ))


if __name__ == "__main__":
    main()
