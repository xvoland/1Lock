#!/usr/bin/env python3
"""Собирает assets/app-icon.ico из PNG.

Зачем он нужен: `rc.exe` вшивает иконку в .exe и на PNG ругается RC2175
«is not in 3.00 format» — ему нужен настоящий контейнер ICO. Раньше иконка
лежала только в assets/app-icon.png, и Windows-сборка падала.

Формат ICO с картинками в BMP, а не в PNG, выбран намеренно: PNG внутри
ICO поддерживается не всеми версиями `rc.exe`, а BMP принимает всегда.

PIL в системе нет, поэтому PNG разбирается вручную: заголовок IHDR, блоки
IDAT со сжатием zlib, обратная распаковка фильтров scanline. На вход берётся
только 8-битный RGBA без чередования — ровно то, что лежит в репозитории.

Запуск: python3 scripts/make_ico.py assets/app-icon.png assets/app-icon.ico
"""

import struct
import sys
import zlib

# Размеры, которые Windows ожидает у иконки приложения. Все — уменьшения
# исходных 128 px, увеличивать нечего: растянет каша, а Windows сама
# отмасштабирует 128 в крупных местах.
SIZES = (16, 24, 32, 48, 64, 128)


def chunks(data):
    """Разбор PNG на куски: (тип, данные)."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "не PNG"
    pos, out = 8, []
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        kind = data[pos + 4 : pos + 8]
        out.append((kind, data[pos + 8 : pos + 8 + length]))
        pos += 12 + length
    return out


def paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode_png(data):
    """PNG 8 бит, RGBA (тип 6), без чередования -> список строк RGBA."""
    header, idat, palette = None, b"", None
    for kind, payload in chunks(data):
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", payload)
        elif kind == b"IDAT":
            idat += payload
        elif kind == b"PLTE":
            palette = payload
    if header is None:
        raise ValueError("нет IHDR")
    width, height, depth, colour, _, _, interlace = header
    if (depth, colour, interlace) != (8, 6, 0):
        raise ValueError(
            f"нужен 8-битный RGBA без чередования, а тут depth={depth} "
            f"colour={colour} interlace={interlace}"
        )
    if palette is not None:
        raise ValueError("палитра не поддерживается")

    raw = zlib.decompress(idat)
    stride = width * 4
    rows, prev, pos = [], bytearray(stride), 0
    for _ in range(height):
        filter_type = raw[pos]
        pos += 1
        line = bytearray(raw[pos : pos + stride])
        pos += stride
        if filter_type == 1:
            for i in range(4, stride):
                line[i] = (line[i] + line[i - 4]) & 0xFF
        elif filter_type == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif filter_type == 3:
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif filter_type == 4:
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                upper_left = prev[i - 4] if i >= 4 else 0
                line[i] = (line[i] + paeth(left, prev[i], upper_left)) & 0xFF
        elif filter_type != 0:
            raise ValueError(f"неизвестный фильтр {filter_type}")
        rows.append(line)
        prev = line
    return width, height, rows


def resize(rows, src_w, src_h, side):
    """Уменьшение усреднением по ячейкам: так края не мылятся."""
    if side == src_w:
        return [bytearray(r) for r in rows]
    out = []
    for y in range(side):
        y0, y1 = y * src_h // side, max((y + 1) * src_h // side, y * src_h // side + 1)
        row = bytearray(side * 4)
        for x in range(side):
            x0, x1 = x * src_w // side, max((x + 1) * src_w // side, x * src_w // side + 1)
            r = g = b = a = n = 0
            for yy in range(y0, min(y1, src_h)):
                src = rows[yy]
                for xx in range(x0, min(x1, src_w)):
                    o = xx * 4
                    r += src[o]
                    g += src[o + 1]
                    b += src[o + 2]
                    a += src[o + 3]
                    n += 1
            o = x * 4
            row[o] = r // n
            row[o + 1] = g // n
            row[o + 2] = b // n
            row[o + 3] = a // n
        out.append(row)
    return out


def dib(rows, side):
    """Картинка для ICO: BITMAPINFOHEADER + BGRA снизу вверх + AND-маска.

    Высота в заголовке вдвое больше: под картинкой идёт прозрачность
    (AND-маска), и она тоже считается частью битмапа.
    """
    header = struct.pack(
        "<IiiHHIIiiII",
        40,          # biSize
        side,        # biWidth
        side * 2,    # biHeight: картинка плюс маска
        1,           # biPlanes
        32,          # biBitCount
        0,           # biCompression: BI_RGB
        0,           # biSizeImage: можно ноль
        0, 0, 0, 0,
    )
    pixels = bytearray()
    for row in reversed(rows):
        for x in range(side):
            o = x * 4
            pixels += bytes((row[o + 2], row[o + 1], row[o], row[o + 3]))

    # AND-маска: по биту на пиксель, каждая строка дополняется до 4 байт.
    # При 32 битах на пиксель альфа уже в самой картинке, поэтому все биты
    # нулевые: маска объявляет «непрозрачно там, где альфа ненулевая».
    mask_stride = ((side + 31) // 32) * 4
    mask = bytes(mask_stride * side)
    return bytes(header) + bytes(pixels) + mask


def build_ico(images):
    """images: список (side, dib_bytes)."""
    count = len(images)
    out = bytearray(struct.pack("<HHH", 0, 1, count))
    offset = 6 + 16 * count
    for side, payload in images:
        out += struct.pack(
            "<BBBBHHII",
            0 if side >= 256 else side,
            0 if side >= 256 else side,
            0,      # bColorCount
            0,      # bReserved
            1,      # wPlanes
            32,     # wBitCount
            len(payload),
            offset,
        )
        offset += len(payload)
    for _, payload in images:
        out += payload
    return bytes(out)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "assets/app-icon.png"
    dst = sys.argv[2] if len(sys.argv) > 2 else "assets/app-icon.ico"
    width, height, rows = decode_png(open(src, "rb").read())
    if width != height:
        raise ValueError(f"нужен квадрат, а тут {width}x{height}")

    images = []
    for side in SIZES:
        if side > width:
            continue
        images.append((side, dib(resize(rows, width, height, side), side)))

    open(dst, "wb").write(build_ico(images))
    print(f"{dst}: {len(images)} размеров {', '.join(str(s) for s, _ in images)}, "
          f"{len(build_ico(images))} байт")


if __name__ == "__main__":
    main()
