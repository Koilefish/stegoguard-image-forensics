"""StegoGuard v2 - a small image forensics scanner (educational, defensive use only).

What it checks
  1. File signature (is a .png really a PNG?)
  2. PNG structure: it walks every chunk, verifies each CRC, flags text/unknown
     chunks and decodes (even compressed) text so keywords can't hide there
  3. Extra data after the real image ending marker
  4. Suspicious keywords (built-in list below + keywords.txt)

Output: readable console log + a Markdown report on the GitHub Actions run page.

Usage:  python scanner.py [folder] [--strict] [--summary report.md]
"""
from dataclasses import dataclass, field
from pathlib import Path
import argparse
import os
import struct
import sys
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

JPEG_SIGNATURE = b"\xff\xd8\xff"
JPEG_END = b"\xff\xd9"

GIF_SIGNATURES = [b"GIF87a", b"GIF89a"]
GIF_END = b"\x3b"

# Built-in keywords. More can be added (one per line) in keywords.txt without
# touching this file.
SUSPICIOUS_WORDS = [
    b"hidden_message",
    b"secret",
    b"password",
    b"token",
    b"api_key",
    b"confidential",
]
KEYWORD_FILE = Path("keywords.txt")

# Chunks that normal PNG files contain. Anything else is reported as unknown.
KNOWN_CHUNKS = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND",
    b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP", b"bKGD", b"hIST",
    b"tRNS", b"eXIf", b"acTL", b"fcTL", b"fdAT", b"pHYs", b"sPLT", b"tIME",
}
TEXT_CHUNKS = {b"tEXt", b"zTXt", b"iTXt"}

MAX_DECOMPRESSED = 1_000_000   # never inflate more than ~1 MB (zip-bomb guard)
PREVIEW_CHARS = 80


# --------------------------------------------------------------------------
# Data containers
# --------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str            # "HIGH" (fails the scan) or "WARN" (needs review)
    message: str
    where: str = ""
    preview: str = ""


@dataclass
class Chunk:
    index: int
    ctype: bytes
    offset: int              # where the chunk starts in the file
    length: int              # size of the chunk's data
    crc_ok: bool
    body: bytes = b""
    note: str = ""

    @property
    def name(self):
        return self.ctype.decode("ascii", errors="replace")

    @property
    def total_size(self):
        return self.length + 12   # 4 length + 4 type + data + 4 CRC


@dataclass
class ScanResult:
    path: Path
    findings: list = field(default_factory=list)
    chunks: list = field(default_factory=list)

    def status(self, strict=False):
        if any(f.severity == "HIGH" for f in self.findings):
            return "SUSPICIOUS"
        if any(f.severity == "WARN" for f in self.findings):
            return "SUSPICIOUS" if strict else "REVIEW"
        return "CLEAN"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def load_keywords():
    """Built-in keywords + keywords.txt (one per line, # = comment)."""
    words = list(SUSPICIOUS_WORDS)
    if KEYWORD_FILE.is_file():
        for line in KEYWORD_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            word = line.lower().encode("utf-8")
            if word not in words:
                words.append(word)
    return words


def safe_preview(data, limit=PREVIEW_CHARS):
    """Printable, single-line preview of raw bytes (never dumps binary)."""
    data = data.strip()
    text = data[:limit].decode("latin-1")
    text = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return text + ("..." if len(data) > limit else "")


def find_offsets(haystack, needle, limit=3):
    offsets, start = [], 0
    while len(offsets) < limit:
        i = haystack.find(needle, start)
        if i == -1:
            break
        offsets.append(i)
        start = i + 1
    return offsets


def inflate(blob):
    return zlib.decompressobj().decompress(blob, MAX_DECOMPRESSED)


def decode_text_chunk(ctype, body):
    """Return (keyword_label, text_bytes) for tEXt / zTXt / iTXt chunks."""
    key_bytes, _, rest = body.partition(b"\x00")
    key = safe_preview(key_bytes, 40)
    try:
        if ctype == b"tEXt":
            return key, rest
        if ctype == b"zTXt":
            return key, inflate(rest[1:])          # rest[0] = compression method
        compressed = rest[0] == 1                   # iTXt: flag, method, lang, translated, text
        text = rest[2:]
        _lang, _, text = text.partition(b"\x00")
        _translated, _, text = text.partition(b"\x00")
        return key, (inflate(text) if compressed else text)
    except (zlib.error, IndexError):
        return key, b""


# --------------------------------------------------------------------------
# PNG analysis
# --------------------------------------------------------------------------
def walk_png(data):
    """Read the PNG chunk by chunk. Returns (chunks, end_position, ended, problem)."""
    chunks = []
    pos = len(PNG_SIGNATURE)
    problem = None
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if end > len(data):
            problem = (f"Chunk {ctype.decode('ascii', 'replace')} at byte {pos} claims "
                       f"{length} bytes but the file ends early.")
            break
        body = data[pos + 8:pos + 8 + length]
        stored_crc = struct.unpack(">I", data[pos + 8 + length:end])[0]
        crc_ok = (zlib.crc32(ctype + body) & 0xFFFFFFFF) == stored_crc
        chunks.append(Chunk(len(chunks), ctype, pos, length, crc_ok, body))
        pos = end
        if ctype == b"IEND":
            return chunks, pos, True, problem
    return chunks, pos, False, problem


def analyze_png(data, keywords):
    findings, chunks = [], []
    trailing_start = None
    decoded_texts = []   # (chunk, label, text)

    if not data.startswith(PNG_SIGNATURE):
        findings.append(Finding("HIGH", "File extension is PNG, but PNG signature is missing."))
    else:
        chunks, pos, ended, problem = walk_png(data)

        for c in chunks:
            where = f"byte offset {c.offset}"
            if not c.crc_ok:
                c.note = "BAD CRC"
                findings.append(Finding("HIGH", f"Bad CRC in {c.name} chunk #{c.index} "
                                                "(chunk was modified or is corrupt).", where))
            if c.ctype in TEXT_CHUNKS:
                label, text = decode_text_chunk(c.ctype, c.body)
                c.note = c.note or f"text metadata ('{label}')"
                decoded_texts.append((c, label, text))
                findings.append(Finding("WARN", f"Text metadata chunk found: {c.name} (keyword '{label}').",
                                        where, safe_preview(text)))
            elif c.ctype not in KNOWN_CHUNKS:
                c.note = c.note or "unknown chunk"
                findings.append(Finding("WARN", f"Unknown or private chunk: {c.name}.",
                                        where, safe_preview(c.body)))

        if problem:
            findings.append(Finding("HIGH", problem))
        if not ended:
            findings.append(Finding("HIGH", "PNG ending marker was not found."))
        else:
            trailing_start = pos
            extra = data[pos:]
            if extra.strip():
                findings.append(Finding("HIGH",
                                        f"Extra data found after PNG ending marker: {len(extra)} bytes.",
                                        f"byte offset {pos} to {len(data)}", safe_preview(extra)))

    def locate(offset):
        if trailing_start is not None and offset >= trailing_start:
            return "after the PNG ending marker"
        for c in chunks:
            if c.offset <= offset < c.offset + c.total_size:
                return f"inside {c.name} chunk #{c.index}"
        return "file header area"

    hits = keyword_hits(data, keywords, locate)

    # Compressed text (zTXt / iTXt) hides keywords from the raw-byte search,
    # so also search the decoded text.
    for c, label, text in decoded_texts:
        lowered = text.lower()
        for word in keywords:
            if word in lowered:
                places = hits.setdefault(word, [])
                tag = f"inside {c.name} chunk #{c.index}"
                if not any(tag in p for p in places):
                    places.append(f"decoded text of {c.name} chunk #{c.index} ('{label}')")

    findings.extend(keyword_findings(hits))
    return findings, chunks


# --------------------------------------------------------------------------
# JPEG / GIF analysis (same checks as the original scanner)
# --------------------------------------------------------------------------
def analyze_simple(data, signatures, end_marker, label, end_name, keywords):
    findings = []
    if not any(data.startswith(sig) for sig in signatures):
        findings.append(Finding("HIGH", f"File extension is {label}, but {label} signature is missing."))

    end_position = data.rfind(end_marker)
    if end_position == -1:
        findings.append(Finding("HIGH", f"{end_name} ending marker was not found."))
        real_end = None
    else:
        real_end = end_position + len(end_marker)
        extra = data[real_end:]
        if extra.strip():
            findings.append(Finding("HIGH",
                                    f"Extra data found after {end_name} ending marker: {len(extra)} bytes.",
                                    f"byte offset {real_end} to {len(data)}", safe_preview(extra)))

    def locate(offset):
        return "after the ending marker" if real_end is not None and offset >= real_end else "inside image data"

    findings.extend(keyword_findings(keyword_hits(data, keywords, locate)))
    return findings


# --------------------------------------------------------------------------
# Keyword helpers
# --------------------------------------------------------------------------
def keyword_hits(data, keywords, locate):
    hits = {}
    lowered = data.lower()
    for word in keywords:
        offsets = find_offsets(lowered, word)
        if offsets:
            hits[word] = [f"byte offset {o} ({locate(o)})" for o in offsets]
    return hits


def keyword_findings(hits):
    return [Finding("HIGH", f"Suspicious keyword found inside file: {word.decode()}", "; ".join(places))
            for word, places in hits.items()]


def scan_image(path, keywords):
    data = path.read_bytes()
    suffix = path.suffix.lower()
    result = ScanResult(path)

    if suffix == ".png":
        result.findings, result.chunks = analyze_png(data, keywords)
    elif suffix in [".jpg", ".jpeg"]:
        result.findings = analyze_simple(data, [JPEG_SIGNATURE], JPEG_END, "JPG/JPEG", "JPEG", keywords)
    elif suffix == ".gif":
        result.findings = analyze_simple(data, GIF_SIGNATURES, GIF_END, "GIF", "GIF", keywords)
    return result


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def print_result(result, strict):
    status = result.status(strict)
    print(f"\nScanning: {result.path}")
    print(f"Status: {status}")
    if result.chunks:
        print("PNG chunks: " + " ".join(c.name for c in result.chunks))
    if not result.findings:
        print("- No issues found by the configured checks.")
    for f in result.findings:
        tag = "" if f.severity == "HIGH" else "[review] "
        print(f"- {tag}{f.message}")
        if f.where:
            print(f"    where:   {f.where}")
        if f.preview:
            print(f"    preview: {f.preview}")

    if os.environ.get("GITHUB_ACTIONS") == "true":
        for f in result.findings:
            level = "error" if f.severity == "HIGH" else "warning"
            print(f"::{level} file={result.path.as_posix()}::{f.message}")


def md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def build_summary(results, keywords, strict, failed):
    out = ["## StegoGuard report", ""]
    out.append(f"**Result: {'FAILED :x:' if failed else 'PASSED :white_check_mark:'}**  "
               f"| images scanned: {len(results)} | keywords loaded: {len(keywords)}")
    out.append("")
    for r in results:
        out.append(f"### `{r.path.as_posix()}` - {r.status(strict)}")
        out.append("")
        if r.chunks:
            out.append("| # | Chunk | Offset | Data bytes | CRC | Note |")
            out.append("|---|-------|--------|------------|-----|------|")
            for c in r.chunks:
                out.append(f"| {c.index} | `{c.name}` | {c.offset} | {c.length} | "
                           f"{'ok' if c.crc_ok else 'BAD'} | {md(c.note)} |")
            out.append("")
        if r.findings:
            out.append("| Severity | Finding | Where | Preview |")
            out.append("|----------|---------|-------|---------|")
            for f in r.findings:
                out.append(f"| {f.severity} | {md(f.message)} | {md(f.where)} | `{md(f.preview)}` |"
                           if f.preview else
                           f"| {f.severity} | {md(f.message)} | {md(f.where)} | |")
        else:
            out.append("No issues found by the configured checks.")
        out.append("")
    return "\n".join(out) + "\n"


def write_summary(text, explicit_path):
    target = explicit_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="StegoGuard image forensics scanner")
    parser.add_argument("folder", nargs="?", default="images", help="folder with images (default: images)")
    parser.add_argument("--strict", action="store_true", help="treat review warnings as failures")
    parser.add_argument("--summary", help="also write the Markdown report to this file")
    args = parser.parse_args()

    image_folder = Path(args.folder)
    if not image_folder.is_dir():
        print(f"Scan error: {args.folder}/ directory not found.")
        return 1

    image_files = []
    for extension in ["*.png", "*.jpg", "*.jpeg", "*.gif"]:
        image_files.extend(image_folder.glob(extension))

    if not image_files:
        print(f"Scan error: no supported image files found in {args.folder}/.")
        return 1

    keywords = load_keywords()
    print(f"Keywords loaded: {len(keywords)} (scanner.py + {KEYWORD_FILE})")

    results = []
    for image in sorted(image_files):
        result = scan_image(image, keywords)
        print_result(result, args.strict)
        results.append(result)

    failed = any(r.status(args.strict) == "SUSPICIOUS" for r in results)
    warnings = sum(1 for r in results if r.status(args.strict) == "REVIEW")
    write_summary(build_summary(results, keywords, args.strict, failed), args.summary)

    if failed:
        print("\nStegoGuard result: FAILED")
        print("Suspicious image data was detected.")
        return 1

    print("\nStegoGuard result: PASSED")
    print("No suspicious image data detected.")
    if warnings:
        print(f"Note: {warnings} image(s) have metadata that deserves a manual review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
