#!/usr/bin/env python3
"""Erzeugt die eingebettete Weltkarte third_party/naturalearth/worldmap.bin aus Natural Earth (gemeinfrei).

Quelle: ne_50m_admin_0_countries.geojson aus github.com/nvkelso/natural-earth-vector (Ordner geojson/).
Die Karte wird vereinfacht (Douglas-Peucker), auf 0,01° gerundet, die Antarktis entfällt. Länder mit demselben
ISO-Code (z. B. Australien und seine Außengebiete) werden zusammengefasst; der Beschriftungspunkt kommt vom Hauptteil.
Dazu kommen Gebiete, die die Ländertabelle von DB-IP kennt, Natural Earth aber nicht einzeln führt (nur als Punkt).

  python3 -I scripts/make_worldmap.py <ne_50m_admin_0_countries.geojson>

Format (nach dem Entpacken mit Deflate, alle Zahlen little-endian):
  "SBWM", Version (1 Byte) = 1, Anzahl Länder (u16)
  je Land: ISO-Code (2 ASCII-Bytes, "--" = keiner), Beschriftungspunkt Länge/Breite (je i16, Hundertstel Grad),
           12 Namen (je u8 Länge + UTF-8) in der Reihenfolge LANGS, Anzahl Ringe (u16),
           je Ring: Anzahl Punkte (u16), erster Punkt (i16 Länge, i16 Breite), danach Differenzen als Zickzack-Varint.
"""
import json
import os
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "third_party", "naturalearth", "worldmap.bin")
LANGS = ["de", "en", "es", "fr", "it", "ja", "ko", "pl", "pt", "ru", "tr", "zh"]
TOLERANCE = 0.02  # Grad (rund 2 km); die Karte zeigt höchstens etwa 100 Pixel je Grad

# Gebiete ohne eigene Fläche in Natural Earth 1:50m: Punkt (Länge, Breite) und Namen in LANGS-Reihenfolge.
EXTRAS = {
    "BQ": (-68.26, 12.18, ["Bonaire, Sint Eustatius und Saba", "Bonaire, Sint Eustatius and Saba", "Bonaire, San Eustaquio y Saba",
                           "Bonaire, Saint-Eustache et Saba", "Bonaire, Sint Eustatius e Saba", "ボネール、シント・ユースタティウスおよびサバ",
                           "네덜란드령 카리브", "Bonaire, Sint Eustatius i Saba", "Países Baixos Caribenhos", "Бонайре, Синт-Эстатиус и Саба",
                           "Bonaire, Sint Eustatius ve Saba", "荷兰加勒比区"]),
    "BV": (3.36, -54.42, ["Bouvetinsel", "Bouvet Island", "Isla Bouvet", "Île Bouvet", "Isola Bouvet", "ブーベ島", "부베 섬", "Wyspa Bouveta",
                          "Ilha Bouvet", "Остров Буве", "Bouvet Adası", "布韦岛"]),
    "CC": (96.87, -12.16, ["Kokosinseln", "Cocos (Keeling) Islands", "Islas Cocos", "Îles Cocos", "Isole Cocos", "ココス (キーリング) 諸島",
                           "코코스 제도", "Wyspy Kokosowe", "Ilhas Cocos", "Кокосовые острова", "Cocos (Keeling) Adaları", "科科斯群岛"]),
    "CX": (105.62, -10.49, ["Weihnachtsinsel", "Christmas Island", "Isla de Navidad", "Île Christmas", "Isola di Natale", "クリスマス島",
                            "크리스마스섬", "Wyspa Bożego Narodzenia", "Ilha do Natal", "Остров Рождества", "Christmas Adası", "圣诞岛"]),
    "GF": (-53.10, 3.95, ["Französisch-Guayana", "French Guiana", "Guayana Francesa", "Guyane", "Guyana francese", "仏領ギアナ",
                          "프랑스령 기아나", "Gujana Francuska", "Guiana Francesa", "Французская Гвиана", "Fransız Guyanası", "法属圭亚那"]),
    "GI": (-5.35, 36.14, ["Gibraltar", "Gibraltar", "Gibraltar", "Gibraltar", "Gibilterra", "ジブラルタル", "지브롤터", "Gibraltar",
                          "Gibraltar", "Гибралтар", "Cebelitarık", "直布罗陀"]),
    "GP": (-61.58, 16.25, ["Guadeloupe", "Guadeloupe", "Guadalupe", "Guadeloupe", "Guadalupa", "グアドループ", "과들루프", "Gwadelupa",
                           "Guadalupe", "Гваделупа", "Guadeloupe", "瓜德罗普"]),
    "MQ": (-61.02, 14.64, ["Martinique", "Martinique", "Martinica", "Martinique", "Martinica", "マルティニーク島", "마르티니크", "Martynika",
                           "Martinica", "Мартиника", "Martinik", "马提尼克"]),
    "RE": (55.53, -21.12, ["Réunion", "Réunion", "Reunión", "La Réunion", "Riunione", "レユニオン島", "레위니옹", "Reunion", "Reunião",
                           "Реюньон", "Réunion", "留尼汪"]),
    "SJ": (15.65, 78.22, ["Svalbard und Jan Mayen", "Svalbard and Jan Mayen", "Svalbard y Jan Mayen", "Svalbard et Jan Mayen",
                          "Svalbard e Jan Mayen", "スバールバル諸島・ヤンマイエン島", "스발바르 얀마옌", "Svalbard i Jan Mayen",
                          "Svalbard e Jan Mayen", "Шпицберген и Ян-Майен", "Svalbard ve Jan Mayen", "斯瓦尔巴群岛和扬马延岛"]),
    "TK": (-171.85, -9.20, ["Tokelau", "Tokelau", "Tokelau", "Tokelau", "Tokelau", "トケラウ諸島", "토켈라우", "Tokelau", "Tokelau",
                            "Токелау", "Tokelau", "托克劳群岛"]),
    "UM": (166.65, 19.28, ["Kleinere Inselbesitzungen der USA", "United States Minor Outlying Islands",
                           "Islas Ultramarinas Menores de los Estados Unidos", "Îles mineures éloignées des États-Unis",
                           "Isole minori esterne degli Stati Uniti", "米領太平洋諸島", "미국령 군소 제도", "Dalekie Wyspy Mniejsze Stanów Zjednoczonych",
                           "Ilhas Menores Distantes dos Estados Unidos", "Внешние малые острова США", "ABD Küçük Dış Adaları", "美国本土外小岛屿"]),
    "YT": (45.14, -12.83, ["Mayotte", "Mayotte", "Mayotte", "Mayotte", "Mayotte", "マヨット島", "마요트", "Majotta", "Mayotte", "Майотта",
                           "Mayotte", "马约特"]),
}


def simplify(points, tol):
    """Douglas-Peucker ohne Rekursion; Anfang und Ende bleiben."""
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    t2 = tol * tol
    while stack:
        a, b = stack.pop()
        ax, ay = points[a]
        bx, by = points[b]
        dx, dy = bx - ax, by - ay
        ll = dx * dx + dy * dy
        best, besti = -1.0, -1
        for i in range(a + 1, b):
            px, py = points[i]
            if ll == 0:
                d = (px - ax) ** 2 + (py - ay) ** 2
            else:
                t = ((px - ax) * dx + (py - ay) * dy) / ll
                t = max(0.0, min(1.0, t))
                d = (px - ax - t * dx) ** 2 + (py - ay - t * dy) ** 2
            if d > best:
                best, besti = d, i
        if besti >= 0 and best > t2:
            keep[besti] = True
            stack.append((a, besti))
            stack.append((besti, b))
    return [p for p, k in zip(points, keep) if k]


def q(v):
    return int(round(v * 100))


def ring_area(r):
    return abs(sum(r[i][0] * r[i - 1][1] - r[i - 1][0] * r[i][1] for i in range(len(r)))) / 2


def zigzag(v):
    return (v << 1) ^ (v >> 31)


def varint(out, v):
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)


def main(path):
    data = json.load(open(path, encoding="utf-8"))
    countries = {}  # Code → {"rings", "label", "names", "main_area"}
    order = []
    anonymous = 0
    for f in data["features"]:
        p = f["properties"]
        code = p.get("ISO_A2_EH") or p.get("ISO_A2") or "-99"
        if code == "AQ":
            continue
        if len(code) != 2 or not code.isalpha():
            anonymous += 1
            code = "--%d" % anonymous  # eigene Fläche ohne Code (z. B. Somaliland), nur zum Zeichnen
        g = f["geometry"]
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        rings = []
        for poly in polys:
            for ring in poly:
                pts = [(x, y) for x, y in ring]
                s = simplify(pts, TOLERANCE)
                if len(s) < 4:
                    # Kleine Insel: grob, aber sichtbar lassen (sonst verschwänden Malta, Singapur, Bahrain …).
                    s = simplify(pts, TOLERANCE / 8)
                    if len(s) < 4:
                        s = pts
                qs = []
                for x, y in s:
                    pt = (q(x), q(y))
                    if not qs or qs[-1] != pt:
                        qs.append(pt)
                if len(qs) >= 3:
                    rings.append(qs)
        area = sum(ring_area(r) for r in rings)
        names = [(p.get("NAME_" + l.upper()) or p.get("NAME_EN") or p.get("NAME") or "").strip() for l in LANGS]
        main = p.get("HOMEPART") == 1
        c = countries.get(code)
        if c is None:
            c = countries[code] = {"rings": [], "label": None, "names": names, "rank": (-1, 0)}
            order.append(code)
        c["rings"].extend(rings)
        rank = (1 if main else 0, area)
        if rank > c["rank"]:
            c["rank"] = rank
            c["label"] = (q(p["LABEL_X"]), q(p["LABEL_Y"]))
            c["names"] = names
    for code, (lon, lat, names) in EXTRAS.items():
        if code in countries:
            raise SystemExit("Extra schon in der Karte: " + code)
        assert len(names) == len(LANGS)
        countries[code] = {"rings": [], "label": (q(lon), q(lat)), "names": names}
        order.append(code)

    out = bytearray(b"SBWM")
    out.append(1)
    out += struct.pack("<H", len(order))
    total = 0
    for code in order:
        c = countries[code]
        out += (code if not code.startswith("--") else "--").encode("ascii")
        out += struct.pack("<hh", *c["label"])
        for n in c["names"]:
            b = n.encode("utf-8")
            if len(b) > 255:
                raise SystemExit("Name zu lang: " + n)
            out.append(len(b))
            out += b
        out += struct.pack("<H", len(c["rings"]))
        for r in c["rings"]:
            if len(r) > 65535:
                raise SystemExit("Ring zu lang")
            total += len(r)
            out += struct.pack("<Hhh", len(r), r[0][0], r[0][1])
            for (x0, y0), (x1, y1) in zip(r, r[1:]):
                varint(out, zigzag(x1 - x0))
                varint(out, zigzag(y1 - y0))
    packed = zlib.compress(bytes(out), 9)[2:-4]  # roher Deflate-Strom (wie System.IO.Compression.DeflateStream)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as fh:
        fh.write(packed)
    print("Länder %d, Punkte %d, roh %d Bytes, gepackt %d Bytes → %s" % (len(order), total, len(out), len(packed), OUT))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
