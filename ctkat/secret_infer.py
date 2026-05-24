"""Role inference for cryptographic function parameters.

Two layers of inference, applied in order:

1. PQC API profile match (suffix-based). Recognizes canonical PQClean-style
   function names like `crypto_kem_dec` even when wrapped in a namespace
   prefix such as `PQCLEAN_KYBER768_CLEAN_crypto_kem_dec`. When matched, the
   profile assigns a role per parameter index — this is the most reliable
   signal.

2. Conservative name-keyword heuristic. Used as a fallback. Only assigns
   `secret` / `public` / `output` roles when the parameter name unambiguously
   matches a known keyword. Generic names (like `key`, `s`, `buf`) are
   intentionally left as `unknown` so the user must confirm.

Scalar (non-pointer, non-array) parameters are flagged as `scalar` — they
are not buffers and don't need taint annotation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .header_parser import FunctionSig, ParamInfo


Role = str  # "secret" | "public" | "output" | "scalar" | "unknown"


@dataclass
class RoleAssignment:
    param: ParamInfo
    role: Role
    reason: str


@dataclass
class InferredFunction:
    signature: FunctionSig
    profile: Optional[str]
    assignments: List[RoleAssignment] = field(default_factory=list)


# --- PQC profiles -------------------------------------------------------------
#
# Each profile is keyed by a canonical *suffix* of the C function name. We
# match either exact equality or a `_`-separated suffix. The role list is
# positional and must match the parameter count.
#
# IMPORTANT: dict iteration order matters here. `_match_profile` returns the
# first matching suffix, so when adding new keys make sure no suffix is a
# longer extension of another (e.g. adding plain `crypto_sign` would shadow
# `crypto_sign_signature` because the loop hits `crypto_sign` first if it's
# listed earlier — list more-specific suffixes before less-specific ones).

_PQC_PROFILES: Dict[str, Tuple[str, List[Role]]] = {
    # KEM
    "crypto_kem_keypair":   ("kem_keypair",   ["output", "output"]),
    "crypto_kem_enc":       ("kem_enc",       ["output", "output", "public"]),
    "crypto_kem_dec":       ("kem_dec",       ["output", "public", "secret"]),
    # Signature (detached signature API)
    "crypto_sign_keypair":  ("sign_keypair",  ["output", "output"]),
    "crypto_sign_signature":("sign_signature",["output", "output", "public", "scalar", "secret"]),
    "crypto_sign_verify":   ("sign_verify",   ["public", "scalar", "public", "scalar", "public"]),
}


def _match_profile(func_name: str) -> Optional[Tuple[str, List[Role]]]:
    for suffix, profile in _PQC_PROFILES.items():
        if func_name == suffix or func_name.endswith("_" + suffix):
            return profile
    return None


# --- Name keyword heuristics --------------------------------------------------
#
# Keep these conservative. Anything not in these sets falls back to `unknown`
# so the user must confirm rather than risk a wrong auto-assignment.

_SECRET_KEYWORDS = frozenset({
    "sk", "secret", "secret_key", "secretkey",
    "private", "private_key", "privatekey",
    "seed", "coins", "noise",
})
_PUBLIC_KEYWORDS = frozenset({
    "pk", "public", "public_key", "publickey",
    "ct", "ciphertext",
    "msg", "message", "input",
})
_OUTPUT_KEYWORDS = frozenset({
    "ss", "shared_secret", "sharedsecret",
    "sig", "signature",
    "out", "output", "result",
})


def _heuristic_role(param: ParamInfo) -> Tuple[Role, str]:
    if not param.is_pointer:
        return "scalar", "non-pointer parameter (not a buffer)"
    nm = param.name.lower()
    if nm in _SECRET_KEYWORDS:
        return "secret", f"name {param.name!r} matches secret keyword"
    if nm in _PUBLIC_KEYWORDS:
        return "public", f"name {param.name!r} matches public keyword"
    if nm in _OUTPUT_KEYWORDS:
        return "output", f"name {param.name!r} matches output keyword"
    return "unknown", "no profile or keyword match — please specify manually"


def infer_function(sig: FunctionSig) -> InferredFunction:
    profile_match = _match_profile(sig.name)
    if profile_match is not None and len(profile_match[1]) == len(sig.params):
        profile_name, roles = profile_match
        assignments = [
            RoleAssignment(
                param=p,
                role=role,
                reason=f"profile={profile_name} arg[{i}]",
            )
            for i, (p, role) in enumerate(zip(sig.params, roles))
        ]
        # Scalar params keep their natural classification when the profile
        # marks them so (e.g. msglen). Buffer params keep the profile role.
        return InferredFunction(signature=sig, profile=profile_name, assignments=assignments)

    assignments: List[RoleAssignment] = []
    for p in sig.params:
        role, reason = _heuristic_role(p)
        assignments.append(RoleAssignment(param=p, role=role, reason=reason))
    return InferredFunction(signature=sig, profile=None, assignments=assignments)


def infer_functions(sigs: List[FunctionSig]) -> List[InferredFunction]:
    return [infer_function(s) for s in sigs]
