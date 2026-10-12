
"""Zero-Day Typosquatting Engine for Phishing Detection.

Detects spelling variations and possible brand impersonation using
Levenshtein distance and compound-domain analysis.

This engine performs local string analysis only. It does not establish
whether a domain is confirmed malicious.
"""

from __future__ import annotations

from dataclasses import dataclass

import tldextract


@dataclass
class TyposquatResult:
    """Container for typosquatting evaluation result."""

    is_typosquat: bool
    matched_brand: str
    edit_distance: int
    similarity_score: float
    reason: str


# Protected brands used for impersonation checks.
PROTECTED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
    "baccredomatic", "banestes", "banestesnet", "magalu", "binance",
    "coinbase", "citrix", "docusign", "adobe", "linkedin", "twitter",
    "telegram", "whatsapp", "usps", "dhl", "fedex", "ups", "allegro",
    "saude", "portaldocliente", "mymaxis", "outlook", "office365",
    "icloud", "dropbox", "spotify", "steam", "roblox", "barclays",
    "hsbc", "santander",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute exact Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if not s2:
        return len(s1)

    previous_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1):
        current_row = [i + 1]

        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)

            current_row.append(
                min(insertions, deletions, substitutions)
            )

        previous_row = current_row

    return previous_row[-1]


class TyposquatEngine:
    """Detect possible brand impersonation and typosquatting."""

    def __init__(self, brands: list[str] | None = None) -> None:
        self.protected_brands = [
            brand.lower() for brand in (brands or PROTECTED_BRANDS)
        ]

    def check_url(self, url: str) -> TyposquatResult:
        """Check the registered domain label and subdomain for brand signals."""
        extracted = tldextract.extract(url)

        subdomain = extracted.subdomain.lower()
        domain = extracted.domain.lower()
        suffix = extracted.suffix.lower()

        # The registered domain label excludes the public suffix.
        # Example: www-hk-google.com -> domain label "www-hk-google".
        tokens = set(subdomain.split("."))
        tokens.update(domain.split("-"))
        tokens.add(domain)

        tokens = {token for token in tokens if len(token) >= 4}

        # Exact brand token embedded in a compound domain:
        # "www-hk-google.com" contains the token "google".
        #
        # Restrict this signal to the registered domain label, not just
        # any occurrence in the full URL or path.
        for brand in self.protected_brands:
            if domain != brand and domain.endswith(f"-{brand}"):
                return TyposquatResult(
                    is_typosquat=True,
                    matched_brand=brand,
                    edit_distance=0,
                    similarity_score=1.0,
                    reason=(
                        f"Possible brand impersonation: '{brand}' appears "
                        f"at the end of compound domain '{domain}.{suffix}'"
                    ),
                )

        best_match_brand = ""
        min_distance = 99
        best_similarity = 0.0

        for token in tokens:
            for brand in self.protected_brands:
                # Avoid flagging the exact registered brand label.
                if token == brand and domain == brand:
                    continue

                distance = levenshtein_distance(token, brand)
                max_length = max(len(token), len(brand))
                similarity = 1.0 - (distance / max_length)

                # Preserve existing near-typo detection.
                is_near_typo = (
                    distance == 1
                    or (distance == 2 and len(brand) >= 6)
                )

                if is_near_typo and domain != brand:
                    if distance < min_distance:
                        min_distance = distance
                        best_match_brand = brand
                        best_similarity = round(similarity, 3)

        if best_match_brand:
            return TyposquatResult(
                is_typosquat=True,
                matched_brand=best_match_brand,
                edit_distance=min_distance,
                similarity_score=best_similarity,
                reason=(
                    f"Possible typosquatting: domain may impersonate "
                    f"'{best_match_brand}' "
                    f"(edit distance={min_distance})"
                ),
            )

        return TyposquatResult(
            is_typosquat=False,
            matched_brand="",
            edit_distance=99,
            similarity_score=0.0,
            reason="No typosquatting signal detected",
        )
