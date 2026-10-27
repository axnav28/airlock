from __future__ import annotations
from dataclasses import dataclass
from .models import Provenance, Sensitivity, Trust


@dataclass(frozen=True)
class Decision:
    allowed: bool
    policy_id: str
    argument: str
    reason: str
    provenance: dict


class PolicyEngine:
    def check(self, operation: str, args: dict[str, Provenance], *, approved_root: str) -> Decision:
        def deny(policy: str, arg: str, reason: str, value: Provenance) -> Decision:
            return Decision(False, policy, arg, reason, value.safe())
        def allow(arg: str, value: Provenance) -> Decision:
            return Decision(True, "ALLOW", arg, "deterministic policy checks passed", value.safe())

        if operation in {"email.send", "email.forward"}:
            to = args.get("to") or args.get("recipient")
            body = args.get("body")
            if not to or not to.sources or to.trust in {Trust.UNKNOWN, Trust.UNTRUSTED, Trust.MIXED}:
                return deny("EMAIL_RECIPIENT_AUTH", "to", "recipient is not backed by trusted user authorization", to or Provenance(value=None))
            if not to.authorization or not to.authorization.explicit:
                return deny("EMAIL_RECIPIENT_AUTH", "to", "no explicit user authorization exists for this destination", to)
            if body and (body.sensitivity in {Sensitivity.SECRET, Sensitivity.PRIVATE} or body.trust != Trust.TRUSTED):
                return deny("EMAIL_DATA_DISCLOSURE", "body", "outbound body contains private/secret or non-trusted derived content", body)
            return allow("to", to)
        if operation == "web.search":
            query = args.get("query")
            if not query or query.sensitivity == Sensitivity.SECRET:
                return deny("SEARCH_SECRET_EGRESS", "query", "secret-derived data cannot be sent to external search", query or Provenance(value=None))
            if query.trust in {Trust.UNKNOWN, Trust.MIXED}:
                return deny("SEARCH_PROVENANCE_REQUIRED", "query", "search query provenance is missing or ambiguous", query)
            return allow("query", query)
        if operation in {"files.read", "files.list"}:
            path = args.get("path")
            if not path or path.trust in {Trust.UNTRUSTED, Trust.MIXED, Trust.UNKNOWN}:
                return deny("FILE_PATH_AUTH", "path", "file path is not independently authorized", path or Provenance(value=None))
            return allow("path", path)
        return Decision(True, "ALLOW", "", "non-sensitive operation", {})
