#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
import xml.etree.ElementTree as ET


def calculate_crap(complexity: float, coverage: float) -> float:
    return (complexity ** 2) * ((1 - coverage) ** 3) + complexity


def iter_methods(path: str) -> list[tuple[str, str, float, float, float]]:
    root = ET.parse(path).getroot()
    methods: list[tuple[str, str, float, float, float]] = []
    for package in root.findall(".//package"):
        package_name = package.attrib.get("name", "")
        if not package_name.startswith("Dp9ik") or package_name.startswith("Dp9ik.Tests"):
            continue

        for class_node in package.findall("./classes/class"):
            class_name = class_node.attrib["name"]
            for method in class_node.findall("./methods/method"):
                coverage = float(method.attrib.get("line-rate", "0"))
                complexity = float(method.attrib.get("complexity", "0"))
                crap = calculate_crap(complexity, coverage)
                methods.append((class_name, method.attrib["name"], complexity, coverage, crap))

    return methods


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage_file")
    parser.add_argument("--max-crap", type=float, default=3.0)
    args = parser.parse_args()

    methods = iter_methods(args.coverage_file)
    failures = [entry for entry in methods if entry[4] >= args.max_crap]

    for class_name, method_name, complexity, coverage, crap in sorted(methods, key=lambda item: item[4], reverse=True):
        print(f"{crap:.2f} comp={complexity:.0f} cov={coverage:.2%} {class_name}.{method_name}")

    if failures:
        print("", file=sys.stderr)
        print(f"CRAP threshold failure: {len(failures)} methods are >= {args.max_crap:.2f}.", file=sys.stderr)
        return 1

    print("", file=sys.stderr)
    print(f"All methods are below the CRAP threshold of {args.max_crap:.2f}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
