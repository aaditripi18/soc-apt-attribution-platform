"""The exact co-used-block combination search (ADR-0005 §D3 implementation,
2026-09-25) selects exactly the partition the original exhaustive
set-partition search selected — proven on real ATT&CK data and on adversarial
synthetic ``g`` functions, for every feature count the old search allowed.

The reference below is the original algorithm, kept verbatim (enumerate every
set partition, keep valid ones, keep locally maximal ones, minimum Σg then
canonical order)."""

from __future__ import annotations

import random
from collections.abc import Callable, Iterator

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import active_groups
from attribution_platform.attribution.comparative_analysis import (
    _find_combination_partition,
    _make_g_of,
)

GOf = Callable[[frozenset[str]], float | None]


def _set_partitions(items: tuple[str, ...]) -> Iterator[tuple[frozenset[str], ...]]:
    n = len(items)

    def helper(i: int, blocks: list[list[str]]) -> Iterator[tuple[frozenset[str], ...]]:
        if i == n:
            yield tuple(frozenset(b) for b in blocks)
            return
        for block in blocks:
            block.append(items[i])
            yield from helper(i + 1, blocks)
            block.pop()
        blocks.append([items[i]])
        yield from helper(i + 1, blocks)
        blocks.pop()

    yield from helper(0, [])


def _reference(features: tuple[str, ...], g_of: GOf) -> tuple[frozenset[str], ...]:
    if len(features) < 2:
        return ()
    atomic = {x: g_of(frozenset({x})) for x in features}

    def admissible(block: frozenset[str]) -> bool:
        if len(block) < 2 or any(atomic[x] is None for x in block):
            return False
        combo = g_of(block)
        return combo is not None and combo < min(atomic[x] or 0.0 for x in block)

    valid = [
        tuple(b for b in p if len(b) >= 2)
        for p in _set_partitions(features)
        if all(admissible(b) for b in p if len(b) >= 2)
    ]
    whole = frozenset(features)

    def improvable(multi: tuple[frozenset[str], ...]) -> bool:
        covered = frozenset().union(*multi) if multi else frozenset()
        blocks = list(multi) + [frozenset({x}) for x in whole - covered]
        return any(
            admissible(blocks[i] | blocks[j])
            for i in range(len(blocks))
            for j in range(i + 1, len(blocks))
        )

    maximal = [p for p in valid if not improvable(p)]
    if not maximal:
        return ()
    best = min(
        maximal,
        key=lambda p: (
            sum(g_of(b) or 0.0 for b in p),
            tuple(sorted(tuple(sorted(b)) for b in p)),
        ),
    )
    return tuple(sorted(best, key=lambda b: tuple(sorted(b))))


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def test_equivalent_on_real_group_profiles(knowledge: AttackKnowledge) -> None:
    """Feature sets drawn from real Group profiles (so real combinations are
    co-used and many are admissible), 2-8 features, 100 draws."""
    g_of = _make_g_of(knowledge)
    from attribution_platform.attack_knowledge.traversal import _uses_index_by_source

    index = _uses_index_by_source(knowledge)
    profiles = [
        sorted(t for t in index.get(str(g["id"]), frozenset()) if t.startswith("attack-pattern--"))
        for g in active_groups(knowledge)
    ]
    profiles = [p for p in profiles if len(p) >= 8]
    rng = random.Random(20260925)
    checked = 0
    for _ in range(100):
        size = rng.randint(2, 8)
        # mix two groups' techniques so partial co-use occurs
        pool = sorted(set(rng.choice(profiles)) | set(rng.choice(profiles)))
        features = tuple(rng.sample(pool, size))
        assert _find_combination_partition(features, g_of) == _reference(features, g_of)
        checked += 1
    assert checked == 100


def _synthetic_g(rng: random.Random, features: tuple[str, ...]) -> GOf:
    """An arbitrary g with the real structure: defined on a downward-closed
    family (co-used sets), undefined above it, values in (0, 1]."""
    maximal = [frozenset(rng.sample(features, rng.randint(1, len(features)))) for _ in range(3)]
    cache: dict[frozenset[str], float | None] = {}

    def g_of(block: frozenset[str]) -> float | None:
        if block not in cache:
            cache[block] = (
                round(rng.uniform(0.01, 1.0), 3) if any(block <= m for m in maximal) else None
            )
        return cache[block]

    return g_of


@pytest.mark.parametrize("seed", range(60))
def test_equivalent_on_adversarial_synthetic_g(seed: int) -> None:
    rng = random.Random(seed)
    features = tuple(f"attack-pattern--{i:02d}" for i in range(rng.randint(2, 8)))
    g_of = _synthetic_g(rng, features)
    assert _find_combination_partition(features, g_of) == _reference(features, g_of)
