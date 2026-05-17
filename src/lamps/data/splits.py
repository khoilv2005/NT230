"""Package-level dataset splitting.

The paper applies splits at the package level so that no file from a given
package appears in both the training and test partitions (paper §5).
"""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Hashable, Iterable, Sequence


def package_level_split(
    items: Sequence[dict],
    package_key: str,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Split `items` into train/val/test partitions grouped by package.

    A *package* is identified by `item[package_key]`. All items belonging to
    the same package are routed to the same partition. Class balance is
    approximately preserved: packages are split independently within each
    label group.

    Args:
        items: Iterable of records, each a dict with `package_key` and `target`.
        package_key: Field used to group records by package.
        train_ratio: Fraction of packages assigned to training.
        val_ratio: Fraction of packages assigned to validation.
        seed: Random seed for shuffling packages.

    Returns:
        Tuple of `(train, val, test)` records.
    """
    test_ratio = 1.0 - train_ratio - val_ratio
    if test_ratio < 0:
        raise ValueError("train_ratio + val_ratio must be <= 1.0")

    rng = random.Random(seed)

    # Group packages by label so each split has both classes.
    by_label: dict[Hashable, dict[str, list[dict]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for item in items:
        label = item.get("target", item.get("label"))
        by_label[label][str(item[package_key])].append(item)

    train: list[dict] = []
    val: list[dict] = []
    test: list[dict] = []

    for label, pkg_to_records in by_label.items():
        packages = sorted(pkg_to_records.keys())
        rng.shuffle(packages)
        n = len(packages)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        for pkg in packages[:n_train]:
            train.extend(pkg_to_records[pkg])
        for pkg in packages[n_train : n_train + n_val]:
            val.extend(pkg_to_records[pkg])
        for pkg in packages[n_train + n_val :]:
            test.extend(pkg_to_records[pkg])

    rng.shuffle(train)
    rng.shuffle(val)
    rng.shuffle(test)

    return train, val, test


def stratified_holdout(
    items: Iterable[dict],
    test_ratio: float = 0.2,
    seed: int = 42,
) -> tuple[list[dict], list[dict]]:
    """Simple stratified holdout used for quick smoke tests."""
    rng = random.Random(seed)
    by_label: dict[Hashable, list[dict]] = defaultdict(list)
    for item in items:
        label = item.get("target", item.get("label"))
        by_label[label].append(item)

    train: list[dict] = []
    test: list[dict] = []
    for label, records in by_label.items():
        rng.shuffle(records)
        cut = int(len(records) * (1 - test_ratio))
        train.extend(records[:cut])
        test.extend(records[cut:])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test
