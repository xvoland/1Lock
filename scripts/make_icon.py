#!/usr/bin/env python3
"""Генерация иконки приложения без внешних зависимостей.

PIL в системе нет, поэтому PNG пишется вручную: заголовок IHDR, один блок
IDAT со сжатием zlib, хвост IEND. Картинка — скруглённый квадрат с
замочной скважиной.

Запуск: python3 make_icon.py /путь/к/AppIcon.png [размер]
"""

import struct
import sys
import zlib

# Цвета в формате RGBA.
BG_TOP = (0x1D, 0x27, 0x3A)
BG_BOTTOM = (0x0E, 0x13, 0x1B)
KEY = (0x59, 0xD3, 0xFF)
KEY_DARK = (0x2E, 0xA8, 0xD8)


def rounded_rect_alpha(x, y, size, radius, inset):
    """Прозрачность пикселя внутри скруглённого квадрата."""
    left = top = inset
    right = bottom = size - inset
    r = radius
    cx = min(max(x, left + r), right - r)
    cy = min(max(y, top + r), bottom - r)
    dx = x - cx
    dy = y - cy
    dist = (dx * dx + dy * dy) ** 0.5
    if x < left or x > right or y < top or y > bottom:
        return 0.0
    # сглаживание края на ширине одного пикселя
    return max(0.0, min(1.0, r - dist + 0.5))


def keyhole_alpha(x, y, size):
    """Замок: круг сверху, трапеция-ножка снизу."""
    cx = size / 2
    cy = size * 0.44
    ring_r = size * 0.135
    # круглая часть
    dx, dy = x - cx, y - cy
    d = (dx * dx + dy * dy) ** 0.5
    inside_circle = max(0.0, min(1.0, ring_r - d + 0.5))
    # ножка: расширяется книзу
    half_top = size * 0.075
    half_bottom = size * 0.145
    if cy < y < size * 0.70:
        t = (y - cy) / (size * 0.70 - cy)
        half = half_top + (half_bottom - half_top) * t
        a = max(0.0, min(1.0, half - abs(x - cx) + 0.5))
        return max(inside_circle, a)
    return inside_circle


def blend(dst, src, alpha):
    return tuple(round(d + (s - d) * alpha) for d, s in zip(dst, src))


def render(size):
    inset = size * 0.055
    radius = size * 0.225
    rows = []
    for y in range(size):
        row = bytearray()
        t = y / (size - 1)
        base = tuple(
            round(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOTTOM)
        )
        for x in range(size):
            a = rounded_rect_alpha(x + 0.5, y + 0.5, size, radius, inset)
            if a <= 0:
                row += bytes((0, 0, 0, 0))
                continue
            px = base
            k = keyhole_alpha(x + 0.5, y + 0.5, size)
            if k > 0:
                shade = 0.5 + 0.5 * (y / size)
                px = blend(KEY_DARK, KEY, shade)
            r, g, b = px
            row += bytes((r, g, b, round(a * 255)))
        rows.append(bytes(row))

    raw = b"".join(b"\x00" + r for r in rows)
    return encode_png(size, size, raw)


def chunk(tag, data):
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def encode_png(w, h, raw):
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "AppIcon.png"
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
    data = render(size)
    with open(out, "wb") as f:
        f.write(data)
    print(f"{out}: {size}x{size}, {len(data)} байт")


if __name__ == "__main__":
    main()
