lazy import re, io, zlib, struct, hashlib, zipfile
lazy import olefile
from pathlib import (Path as P, PurePath as PP)
from typing import Optional, Dict, Any, Generator

buf = memoryview

candidate = PP("candidate")
swf = PP("swf")

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def safe_name(s: str) -> str:
    """Replace characters that Windows forbids in a filename and cap the length"""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', s)[:180]


def is_zlib(data: buf) -> bool:
    """Check if the data is a valid zlib stream (RFC1950) by checking the header and checksum."""
    return (len(data) >= 2 and (data[0] & 0x0F) == 8
            and ((data[0] << 8) + data[1]) % 31 == 0)


def zlib_decompress(data: buf) -> Optional[buf]:
    """RFC1950 zlib, or fallback to RFC1951 raw deflate"""
    if is_zlib(data):
        try:
            d = zlib.decompressobj(15)
            out = buf(d.decompress(data) + d.flush())
            if out:
                return out
        except zlib.error:
            pass
    try:
        d = zlib.decompressobj(-15)
        return buf(d.decompress(data) + d.flush())
    except zlib.error:
        return None


def scan_swf(data: buf, tag: str) -> list[tuple[str, buf]]:
    """Scan for SWF signatures and return (name, view) pairs without writing to disk."""
    hits: list[tuple[str, buf]] = []
    n = 0
    i = 0
    while True:
        m = re.search(b'(FWS|CWS|ZWS)', data[i:])
        if not m:
            break
        off = i + m.start()
        sig = data[off:off+3]
        if off + 8 > len(data):
            break
        ver = data[off+3]
        length = int.from_bytes(data[off+4:off+8], "little")
        if not (8 <= length <= 300 * 1024 * 1024):
            i = off + 3
            continue
        try:
            if sig == b"FWS":
                blob = data[off:off + length]
                if len(blob) == length:
                    hits.append((safe_name(f"{tag}-{n:03d}.swf"), blob))
                    n += 1
            elif sig == b"CWS":
                d = zlib.decompressobj()
                body = buf(d.decompress(data[off+8:]) + d.flush())
                need = length - 8
                if len(body) >= need:
                    raw = b"FWS" + bytes([ver]) + length.to_bytes(4, "little") + body[:need]
                    hits.append((safe_name(f"{tag}-{n:03d}-cws.swf"), buf(raw)))
                    n += 1
        except Exception:
            pass
        i = off + 3
    return hits


def handle_blob(blob: buf, tag: str) -> list[tuple[str, buf]]:
    """Recursively collect SWF views from a decompressed OLE/ZIP/raw payload."""
    hits = scan_swf(blob, tag)
    if blob[:8] == OLE_MAGIC:
        try:
            sub = olefile.OleFileIO(io.BytesIO(blob))
            hits += walk_ole(sub, tag + "_ole")
            sub.close()
        except Exception as e:
            print("  OLE 失败:", e)
    elif blob[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                for info in z.infolist():
                    hits += scan_swf(
                        buf(z.read(info)),
                        tag + "_zip_" + info.filename.replace("/", "_"))
        except Exception as e:
            print("  ZIP 失败:", e)
    return hits


def walk_ole(ole: olefile.OleFileIO, tag: str) -> list[tuple[str, buf]]:
    """Walk all streams of an OLE document and collect SWF views recursively."""
    hits: list[tuple[str, buf]] = []
    for entry in ole.listdir():
        name = "/".join(entry)
        try:
            data = buf(ole.openstream(entry).read())
        except Exception:
            continue
        print(f"  [OLE] {name}: {len(data)} head={data[:8].hex()}")
        hits += scan_swf(data, safe_name(tag + "_" + name.replace("/", "_")))
        if data[:8] == OLE_MAGIC:
            try:
                sub = olefile.OleFileIO(io.BytesIO(data))
                hits += walk_ole(sub, tag + "_" + safe_name(name))
                sub.close()
            except Exception:
                pass
    return hits


def flush_hits(hits: list[tuple[str, buf]], collected: Dict[str, tuple[str, bytes]]) -> int:
    """Copy each view into ``collected`` as ``bytes`` and release the view.

    This is the point where the intermediate decompressed payload can be
    freed: once every view derived from it has been released and the
    caller drops its own reference, the underlying bytes are reclaimed.
    """
    for name, view in hits:
        h = hashlib.md5(view).hexdigest()
        if h not in collected:
            collected[h] = (name, bytes(view))
        view.release()
    return len(hits)


def iter_records(data: buf, start=0, end=None, path=PP("")) -> Generator[Dict[str, Any], None, None]:
    if end is None:
        end = len(data)
    off = start
    while off + 8 <= end:
        ver_inst, rec_type, rec_len = struct.unpack_from("<HHI", data, off)
        rec_ver = ver_inst & 0xF
        body_start = off + 8
        body_end = body_start + rec_len
        if body_end > end:
            break
        yield dict(path=path, offset=off, rec_ver=rec_ver,
                   rec_type=rec_type, rec_len=rec_len,
                   body_start=body_start, body_end=body_end)
        if rec_ver == 0xF:
            yield from iter_records(data, body_start, body_end,
                                    path / f"/{rec_type:x}")
        off = body_end


def parse_pps(pps_path: P, outdir: P = P("ExtractedArtifacts"), debug: bool = False):
    """Extract unique SWFs from a .pps into ``outdir / swf``."""
    outdir.mkdir(exist_ok=True, parents=True)
    final_dir = outdir / swf
    final_dir.mkdir(exist_ok=True)
    collected: Dict[str, tuple[str, bytes]] = {}

    ole = olefile.OleFileIO(pps_path.read_bytes())
    names = ["/".join(e) for e in ole.listdir()]  # type: ignore
    print("OLE 流:", *names, sep="\n  ")

    total = 0
    if "Pictures" in names:
        pic = buf(ole.openstream("Pictures").read())  # type: ignore
        print(f"Pictures: {len(pic)} head={pic[:8].hex()}")
        total += flush_hits(handle_blob(pic, "pictures"), collected)
        pic.release()
        del pic

    ppt = buf(ole.openstream("PowerPoint Document").read())  # type: ignore
    ole.close()
    print(f"PowerPoint Document: {len(ppt)} head={ppt[:8].hex()}")

    REC_EXOLEOBJSTG = 0x1011
    idx = 0
    for r in iter_records(ppt):
        if r["rec_type"] != REC_EXOLEOBJSTG:
            continue
        body = ppt[r["body_start"]:r["body_end"]]
        if len(body) < 4:
            continue
        persistent_size = struct.unpack_from("<I", body, 0)[0]
        payload = body[4:]
        compressed = (len(payload) != persistent_size)
        tag = f"exoleobjstg_{idx:03d}"
        if debug:
            (outdir / (tag + "_raw.bin")).write_bytes(payload)
        print(f"\n[{tag}] persistent={persistent_size} "
              f"payload={len(payload)} compressed={compressed} "
              f"head={payload[:8].hex()}")

        if compressed:
            dec = zlib_decompress(payload)
            if dec:
                print(f"  deflate -> {len(dec)} head={dec[:8].hex()}")
                if debug:
                    (outdir / (tag + "_dec.bin")).write_bytes(dec)
                total += flush_hits(handle_blob(dec, tag + "_dec"), collected)
                dec.release()
                del dec
            else:
                print("  deflate 失败")
        else:
            total += flush_hits(handle_blob(payload, tag), collected)
        idx += 1

    for h, (name, blob) in collected.items():
        (final_dir / name).write_bytes(blob)

    print(f"\n=== ExOleObjStg {idx} 个，扫描命中 {total} 次，"
          f"唯一 SWF {len(collected)} 个 -> {final_dir} ===")
    for h, (name, blob) in collected.items():
        print(f"  {name}  {len(blob)} bytes")
    return collected


if __name__ == "__main__":
    d = P(input("Directory: "))
    if d.is_dir():
        for pps in d.rglob("*.pps"):
            parse_pps(pps, P(pps.stem))