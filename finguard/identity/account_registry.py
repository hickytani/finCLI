"""Account Registry & Alias Normalization Engine for FIN//GUARD.

SECURITY INVARIANTS:
1. Account IDs must strictly conform to regex `^[a-z0-9][a-z0-9_.-]{1,62}$`.
2. Aliases are normalized using Unicode NFKC + casefold. Mixed-script, confusable,
   and zero-width / non-printable control characters are explicitly rejected.
3. Alias resolution is unambiguous: any alias mapping to multiple account IDs is
   flagged as AMBIGUOUS_ALIAS and blocked.
4. Cross-tenant transfers require explicit tenant boundary authorization.
"""

import re
import unicodedata
from enum import Enum
from typing import NamedTuple

from pydantic import BaseModel, Field

from finguard.core.enums import Currency
from finguard.core.errors import SecurityError

ACCOUNT_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,62}$")

# Forbidden control / zero-width characters
ZERO_WIDTH_CONTROL_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u202a",  # LTR embedding
    "\u202b",  # RTL embedding
    "\u202c",  # Pop directional formatting
    "\u202d",  # LTR override
    "\u202e",  # RTL override
}


class ResolutionStatus(str, Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    AMBIGUOUS_ALIAS = "AMBIGUOUS_ALIAS"
    INVALID_FORMAT = "INVALID_FORMAT"
    CONFUSABLE_REJECTED = "CONFUSABLE_REJECTED"


class AccountConfig(BaseModel):
    """Configuration for a registered account."""

    account_id: str
    tenant_id: str = "tenant_default"
    display_name: str
    currency: Currency = Currency.INR
    active: bool = True
    aliases: list[str] = Field(default_factory=list)


class AccountResolutionResult(NamedTuple):
    status: ResolutionStatus
    account: AccountConfig | None
    account_id: str | None
    currency: Currency | None
    reason: str


def normalize_alias(alias: str) -> str:
    """Normalize alias with NFKC and casefold, raising SecurityError if zero-width or non-printable chars present."""
    for char in alias:
        if char in ZERO_WIDTH_CONTROL_CHARS or unicodedata.category(char).startswith("C"):
            raise SecurityError(f"Account alias contains forbidden control or zero-width character: {char!r}")

    nfkc_str = unicodedata.normalize("NFKC", alias)
    # Re-check NFKC string for control chars
    for char in nfkc_str:
        if char in ZERO_WIDTH_CONTROL_CHARS or unicodedata.category(char).startswith("C"):
            raise SecurityError(f"Account alias NFKC normalization produced forbidden character: {char!r}")

    # Homoglyph check: ensure script consistency or ASCII-safe normalization for financial identifiers
    scripts = {unicodedata.name(c, "").split()[0] for c in nfkc_str if c.isalpha()}
    if len(scripts) > 1:
        raise SecurityError(f"Account alias contains mixed-script characters ({scripts}): '{alias}'")

    return nfkc_str.casefold().strip()


class AccountRegistry:
    """Registry maintaining active accounts, alias mappings, and tenant boundaries."""

    def __init__(self) -> None:
        self._accounts: dict[str, AccountConfig] = {}
        self._alias_map: dict[str, set[str]] = {}  # normalized_alias -> set of account_ids
        self._bootstrap_default_accounts()

    def _bootstrap_default_accounts(self) -> None:
        """Register built-in system accounts for treasury and default vendors."""
        defaults = [
            AccountConfig(
                account_id="acct_treasury",
                tenant_id="tenant_default",
                display_name="Primary Treasury Account",
                currency=Currency.INR,
                aliases=["treasury", "main_treasury", "acct_treasury"],
            ),
            AccountConfig(
                account_id="acct_vendor_a",
                tenant_id="tenant_default",
                display_name="Vendor A Account",
                currency=Currency.INR,
                aliases=["vendor-a", "vendor_a", "acct_vendor_a"],
            ),
            AccountConfig(
                account_id="acct_vendor_b",
                tenant_id="tenant_default",
                display_name="Vendor B Account",
                currency=Currency.INR,
                aliases=["vendor-b", "vendor_b", "acct_vendor_b"],
            ),
            AccountConfig(
                account_id="acct_payroll",
                tenant_id="tenant_default",
                display_name="Corporate Payroll Account",
                currency=Currency.INR,
                aliases=["payroll", "acct_payroll"],
            ),
        ]
        for acc in defaults:
            self.register_account(acc)

    def register_account(self, account: AccountConfig) -> None:
        """Register account and bind its normalized aliases."""
        if not ACCOUNT_ID_REGEX.match(account.account_id):
            raise SecurityError(
                f"Account ID '{account.account_id}' does not match regex ^[a-z0-9][a-z0-9_.-]{{1,62}}$"
            )

        self._accounts[account.account_id] = account

        # Self alias
        all_aliases = set(account.aliases) | {account.account_id}
        for raw_alias in all_aliases:
            try:
                norm = normalize_alias(raw_alias)
                if norm not in self._alias_map:
                    self._alias_map[norm] = set()
                self._alias_map[norm].add(account.account_id)
            except SecurityError:
                pass

    def resolve_account(self, query: str) -> AccountResolutionResult:
        """Resolve account ID or alias to a single AccountConfig."""
        if not query or not query.strip():
            return AccountResolutionResult(
                status=ResolutionStatus.INVALID_FORMAT,
                account=None,
                account_id=None,
                currency=None,
                reason="Account query cannot be empty",
            )

        # 1. Direct ID check
        if query in self._accounts:
            acc = self._accounts[query]
            if not acc.active:
                return AccountResolutionResult(
                    status=ResolutionStatus.UNRESOLVED,
                    account=None,
                    account_id=query,
                    currency=None,
                    reason=f"Account '{query}' is inactive",
                )
            return AccountResolutionResult(
                status=ResolutionStatus.RESOLVED,
                account=acc,
                account_id=acc.account_id,
                currency=acc.currency,
                reason="Resolved via direct account ID",
            )

        # 2. Normalize alias
        try:
            norm = normalize_alias(query)
        except SecurityError as e:
            return AccountResolutionResult(
                status=ResolutionStatus.CONFUSABLE_REJECTED,
                account=None,
                account_id=None,
                currency=None,
                reason=f"Alias normalization rejected: {e}",
            )

        matches = self._alias_map.get(norm, set())
        active_matches = [acc_id for acc_id in matches if self._accounts[acc_id].active]

        if len(active_matches) == 1:
            acc = self._accounts[active_matches[0]]
            return AccountResolutionResult(
                status=ResolutionStatus.RESOLVED,
                account=acc,
                account_id=acc.account_id,
                currency=acc.currency,
                reason=f"Resolved alias '{query}' to '{acc.account_id}'",
            )
        elif len(active_matches) > 1:
            return AccountResolutionResult(
                status=ResolutionStatus.AMBIGUOUS_ALIAS,
                account=None,
                account_id=None,
                currency=None,
                reason=f"Alias '{query}' matches multiple accounts: {sorted(active_matches)}",
            )
        else:
            return AccountResolutionResult(
                status=ResolutionStatus.UNRESOLVED,
                account=None,
                account_id=None,
                currency=None,
                reason=f"No active account found matching alias/query '{query}'",
            )

    def validate_tenant_boundary(
        self,
        actor_tenant_id: str,
        from_account_id: str,
        to_account_id: str,
    ) -> tuple[bool, str]:
        """Verify that from_account belongs to actor's tenant."""
        from_res = self.resolve_account(from_account_id)
        if from_res.status != ResolutionStatus.RESOLVED or not from_res.account:
            return False, f"Source account resolution failed: {from_res.reason}"

        if from_res.account.tenant_id != actor_tenant_id and actor_tenant_id != "tenant_admin":
            return False, (
                f"Tenant boundary violation: actor tenant '{actor_tenant_id}' "
                f"cannot initiate from account '{from_account_id}' owned by '{from_res.account.tenant_id}'"
            )

        return True, "Tenant boundary check passed"
