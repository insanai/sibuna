#!/usr/bin/env python3
"""Reproduce the bounded geographic asset from pinned Natural Earth 5.1.2 GeoJSON."""
import hashlib
import json
from pathlib import Path
import struct
import sys

SOURCE_SHA256 = "6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f"
ROOT = Path(__file__).resolve().parents[1]


def build(path):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise SystemExit("Natural Earth source checksum mismatch")
    rings = []
    centers = {}
    vertices = 0
    for feature in json.loads(data)["features"]:
        code = feature["properties"]["ISO_A2_EH"]
        if len(code) != 2 or not code.isascii() or not code.isalpha():
            code = "ZZ"
        props = feature["properties"]
        if code != "ZZ":
            centers[code] = (round(props["LABEL_X"] * 100), round(props["LABEL_Y"] * 100))
        geometry = feature["geometry"]
        polygons = geometry["coordinates"]
        if geometry["type"] == "Polygon":
            polygons = [polygons]
        else:
            assert geometry["type"] == "MultiPolygon"
        for polygon in polygons:
            for ring in polygon:
                # Quantization is bounded to .005 degrees. Remove consecutive duplicates;
                # preserve the publisher's low-resolution boundary and closed ring ordering.
                points = []
                for lon, lat in ring:
                    assert -180.001 <= lon <= 180.001 and -90 <= lat <= 90
                    point = (round(lon * 100), round(lat * 100))
                    if not points or points[-1] != point:
                        points.append(point)
                if len(points) < 4:
                    continue
                assert points[0] == points[-1]
                vertices += len(points)
                rings.append((code.encode(), points))
    assert vertices <= 16384 and len(rings) <= 1024
    output = bytearray(b"SBG2" + struct.pack("<HH", len(centers), len(rings)))
    for code, point in sorted(centers.items()):
        output += code.encode() + struct.pack("<hh", *point)
    for code, points in rings:
        output += code + struct.pack("<H", len(points))
        for point in points:
            output += struct.pack("<hh", *point)
    assert len(output) <= 128 * 1024
    (ROOT / "apps/console-ui/web/assets/world-110m.bin").write_bytes(output)
    print(f"console-geometry: {len(rings)} rings, {vertices} vertices, {len(output)} bytes")


if __name__ == "__main__":
    build(Path(sys.argv[1]))
