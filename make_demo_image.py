from pathlib import Path
import struct
import zlib

mode = Path("lab_mode.txt").read_text(encoding="utf-8").strip().lower()

# clean      -> a normal image, the scan should pass
# suspicious -> harmless demo text appended AFTER the PNG ending marker
# metadata   -> harmless demo text hidden INSIDE a compressed PNG text chunk (zTXt)
if mode not in ["clean", "suspicious", "metadata"]:
    raise SystemExit("lab_mode.txt must contain one of: clean, suspicious, metadata")

Path("images").mkdir(exist_ok=True)

def png_chunk(chunk_type, data):
    """Create a PNG chunk with length, type, data, and CRC."""
    return (
        struct.pack(">I", len(data))
        + chunk_type
        + data
        + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    )

def create_demo_png(width=300, height=300, extra_chunks=b""):
    """Create a valid RGB PNG image using only Python standard library.

    extra_chunks are inserted between the pixel data (IDAT) and the end marker (IEND).
    """
    png_signature = b"\x89PNG\r\n\x1a\n"

    # PNG header: width, height, bit depth 8, color type 2 = RGB
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)

    raw_rows = []
    for y in range(height):
        row = bytearray()
        row.append(0)  # PNG filter type 0: no filter
        for x in range(width):
            r = (x * 255) // width
            g = (y * 255) // height
            b = 160
            row.extend([r, g, b])
        raw_rows.append(bytes(row))

    compressed_pixels = zlib.compress(b"".join(raw_rows))

    return (
        png_signature
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", compressed_pixels)
        + extra_chunks
        + png_chunk(b"IEND", b"")
    )

if mode == "metadata":
    # zTXt layout: keyword, NUL byte, compression method (0), zlib-compressed text.
    # Because the text is compressed, the keyword never appears in the raw file bytes.
    hidden_text = b"CONFIDENTIAL: harmless demo text hidden inside a compressed PNG metadata chunk."
    ztxt_data = b"Comment\x00\x00" + zlib.compress(hidden_text)
    png_data = create_demo_png(300, 300, extra_chunks=png_chunk(b"zTXt", ztxt_data))
else:
    # Larger valid 300x300 PNG image.
    png_data = create_demo_png(width=300, height=300)

if mode == "suspicious":
    png_data += b"\nCONFIDENTIAL CLASSIFIED: This is harmless demo hidden data for the StegoGuard lab.\n"

Path("images/student_image.png").write_bytes(png_data)

print(f"Created images/student_image.png in {mode} mode")
print(f"Image size: {len(png_data)} bytes")
