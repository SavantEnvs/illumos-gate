#!/usr/bin/env python3
"""Regenerates mayhem/smbios/kat/table.bin and the seed corpus in mayhem/fuzz_smbios/testsuite/.

Seeds are `<flavour> <major> <minor> <structure table>` (see fuzz_smbios.c). Not run by the build:
the outputs are committed.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def structure(typ, hdl, body, strings=()):
    """One SMBIOS structure: 4-byte header, formatted body, string set terminated by an extra NUL."""
    out = struct.pack("<BBH", typ, 4 + len(body), hdl) + bytes(body)
    if strings:
        for s in strings:
            out += s.encode() + b"\0"
        out += b"\0"
    else:
        out += b"\0\0"
    return out


def bios():
    body = bytearray()
    body += struct.pack("<BBHBB", 1, 2, 0xE000, 3, 0xFF)   # vendor, version, segment, date, romsize
    body += struct.pack("<Q", 0x0000000000099B90)           # characteristics
    body += bytes([0x03, 0x0C])                              # extension bytes
    body += bytes([2, 7, 0xFF, 0xFF])                        # bios 2.7, ec unknown
    return structure(0, 0x0000, body, ["Mayhem BIOS Vendor", "V2.07.1", "11/10/2026"])


def system():
    body = bytearray()
    body += struct.pack("<BBBB", 1, 2, 3, 4)                 # manufacturer, product, version, serial
    body += bytes(range(0x10, 0x20))                         # uuid
    body += struct.pack("<BBB", 6, 5, 6)                     # wakeup (power switch), sku, family
    return structure(1, 0x0001, body,
                     ["Acme Corp", "Rocket 9000", "rev-C", "SN-0042", "SKU-77", "Rocket Family"])


def chassis(contained=True):
    """contained=False emits no contained-element records (cn=0): smbios_info_chassis_elts() overruns its
    heap buffer whenever cn > 0, so the seeds avoid it and the fuzzer has to find that path itself."""
    body = bytearray()
    body += struct.pack("<BBBB", 1, 0x87, 2, 3)              # manufacturer, type(lock|rack mount 7), version, serial
    body += struct.pack("<BBBBB", 4, 3, 3, 3, 2)             # asset, bustate, psstate, thstate, security
    body += struct.pack("<I", 0xCAFEF00D)                    # oem
    if contained:
        body += struct.pack("<BBBB", 2, 1, 1, 3)             # uheight, cords, elems, elemlen
        body += bytes([0x04, 0x01, 0x01])                    # one contained element
    else:
        body += struct.pack("<BBBB", 2, 1, 0, 0)
    body += bytes([5])                                       # sku
    return structure(3, 0x0003, body,
                     ["Acme Chassis", "ch-1.0", "CH-SERIAL", "ASSET-9", "CH-SKU"])


def oemstrings():
    return structure(11, 0x000B, bytes([3]), ["oem-one", "oem-two", "oem-three"])


def lang():
    body = bytes([2, 1]) + bytes(15) + bytes([1])           # 2 languages, abbreviated format, cur=1
    return structure(13, 0x000D, body, ["enUS", "frFR"])


def memdevice(hdl, size_mb, speed, dloc, bloc, form=9, mtype=26, ext_mb=0):
    body = bytearray()
    body += struct.pack("<HHHH", 0x0010, 0xFFFE, 72, 64)     # array, error, total/data width
    body += struct.pack("<H", size_mb)
    body += struct.pack("<BBBBB", form, 0, 1, 2, mtype)      # form, set, dloc, bloc, type
    body += struct.pack("<HH", 0x0080, speed)                # flags, speed
    body += struct.pack("<BBBB", 3, 4, 5, 6)                 # manufacturer, serial, asset, part
    body += struct.pack("<BIH", 2, ext_mb, speed)                 # attrs(rank), extsize, clkspeed
    return structure(17, hdl, body,
                     [dloc, bloc, "Micron", "DIMM-SN-%d" % hdl, "ASSET", "MTA18ASF2G72PDZ"])


def eot():
    return structure(127, 0xFEFF, b"")


def generic(typ, hdl, length, fill=1, strings=()):
    return structure(typ, hdl, bytes([fill]) * (length - 4), strings)


def kat_table(contained=True):
    return (bios() + system() + chassis(contained) + oemstrings() + lang()
            + memdevice(0x1100, 16384, 3200, "DIMM_A1", "BANK 0")
            + memdevice(0x1101, 0x7FFF, 2666, "DIMM_B1", "BANK 1", form=2, mtype=24, ext_mb=65536)
            + eot())


def full_table():
    parts = [bios(), system(), chassis(False), oemstrings(), lang()]
    h = 0x0100
    for typ, ln, strs in [
        (2, 0x0F, ["Acme", "Board-1", "r1", "BSN", "asset", "loc"]),
        (4, 0x30, ["CPU0", "Intel", "Xeon", "v1", "sn", "asset", "PN"]),
        (7, 0x1B, ["L1 Cache"]), (8, 0x09, ["J1", "J2"]), (9, 0x11, ["PCI1"]),
        (10, 0x06, ["Onboard Video"]), (12, 0x05, ["cfg"]), (16, 0x17, []),
        (19, 0x1F, []), (20, 0x23, []), (22, 0x1A, ["Front", "Li", "1", "2", "3", "4", "5"]),
        (26, 0x16, ["V1"]), (27, 0x0F, []), (28, 0x16, ["T1"]), (29, 0x16, ["I1"]),
        (36, 0x10, []), (39, 0x16, ["PSU", "A", "B", "C", "D", "E", "F"]),
        (41, 0x0B, ["Dev1"]), (43, 0x1F, ["x"]), (45, 0x14, ["fw", "1.0"]),
        (46, 0x09, ["p"]), (126, 0x04, []),
    ]:
        parts.append(generic(typ, h, ln, 1, strs))
        h += 1
    parts.append(memdevice(0x1100, 8192, 2400, "DIMM_A1", "BANK 0"))
    parts.append(eot())
    return b"".join(parts)


def seed(flavour, major, minor, table):
    return bytes([flavour, major, minor]) + table


def known_findings():
    kf = os.path.join(HERE, "known-findings")
    d = os.path.join(kf, "chassis-elts-heap-overflow")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "reproducer"), "wb") as f:
        f.write(seed(1, 2, 7, chassis(True) + eot()))


def main():
    known_findings()
    kat = os.path.join(HERE, "kat")
    os.makedirs(kat, exist_ok=True)
    with open(os.path.join(kat, "table.bin"), "wb") as f:
        f.write(kat_table())

    ts = os.path.join(HERE, "..", "fuzz_smbios", "testsuite")
    os.makedirs(ts, exist_ok=True)
    seeds = {
        "basic-v30": seed(0, 3, 0, kat_table(False)),
        "basic-v21": seed(1, 2, 7, kat_table(False)),
        "full-v30": seed(0, 3, 4, full_table()),
        "full-v21": seed(1, 2, 8, full_table()),
        "min-bios-system": seed(0, 3, 0, bios() + system() + eot()),
        "min-memdevice": seed(1, 2, 7, memdevice(0x1100, 4096, 1600, "A", "B") + eot()),
        "chassis-only": seed(1, 2, 7, chassis(False) + eot()),
        "oem-lang": seed(0, 3, 0, oemstrings() + lang() + eot()),
    }
    for name, data in seeds.items():
        with open(os.path.join(ts, name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    sys.exit(main())
