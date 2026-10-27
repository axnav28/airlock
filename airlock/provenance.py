from __future__ import annotations
from typing import Any
from .models import Authorization, Provenance, Sensitivity, Trust


def trusted(value: Any, source: str, sensitivity: Sensitivity = Sensitivity.PUBLIC,
            authorization: Authorization | None = None) -> Provenance:
    return Provenance(value=value, sources=[source], trust=Trust.TRUSTED,
                      sensitivity=sensitivity, authorization=authorization)


def untrusted(value: Any, source: str, sensitivity: Sensitivity = Sensitivity.PUBLIC) -> Provenance:
    return Provenance(value=value, sources=[source], trust=Trust.UNTRUSTED, sensitivity=sensitivity)


def derive(value: Any, *inputs: Provenance, transformation: str) -> Provenance:
    sources: list[str] = []
    transformations: list[str] = [transformation]
    trusts = set()
    sensitivities = set()
    auths = [x.authorization for x in inputs if x.authorization]
    for item in inputs:
        for source in item.sources:
            if source not in sources:
                sources.append(source)
        trusts.add(item.trust)
        sensitivities.add(item.sensitivity)
        transformations.extend(item.transformations)
    trust = Trust.TRUSTED if trusts == {Trust.TRUSTED} else (Trust.UNTRUSTED if trusts == {Trust.UNTRUSTED} else Trust.MIXED)
    if Trust.UNKNOWN in trusts or not trusts:
        trust = Trust.UNKNOWN
    sensitivity = Sensitivity.SECRET if Sensitivity.SECRET in sensitivities else (
        Sensitivity.PRIVATE if Sensitivity.PRIVATE in sensitivities else (
            Sensitivity.UNKNOWN if Sensitivity.UNKNOWN in sensitivities else Sensitivity.PUBLIC))
    authorization = auths[0] if len(auths) == len(inputs) and auths and all(a == auths[0] for a in auths) else None
    return Provenance(value=value, sources=sources, trust=trust, sensitivity=sensitivity,
                      transformations=transformations[:32], authorization=authorization)


def copy_value(item: Provenance) -> Provenance:
    return item.model_copy(deep=True)


def concat(*items: Provenance, separator: str = "") -> Provenance:
    return derive(separator.join(str(item.value) for item in items), *items, transformation="concatenate")
