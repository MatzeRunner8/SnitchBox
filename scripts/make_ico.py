# Packt icon_<N>.png aus einem Ordner in eine Windows-.ico (PNG-Einträge, 16–256 px).
import struct, sys, os
src, out = sys.argv[1], sys.argv[2]
sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
entries = [(open(os.path.join(src, f"icon_{s}.png"), "rb").read(), s) for s in sizes]
head = struct.pack("<HHH", 0, 1, len(entries))
offset = 6 + 16*len(entries)
dirs, blobs = b"", b""
for data, s in entries:
    dirs += struct.pack("<BBBBHHII", s if s<256 else 0, s if s<256 else 0, 0, 0, 1, 32, len(data), offset+len(blobs))
    blobs += data
open(out,"wb").write(head+dirs+blobs)
