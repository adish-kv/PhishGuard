"""Zero-Day Typosquatting Engine for Phishing Detection.

Implements string similarity and edit distance metrics (Levenshtein Distance)
against top global brands to detect zero-day typosquatting, character substitution,
and brand impersonation without relying solely on exact keyword lookups.
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


# Top global protected brands for typosquatting checks
PROTECTED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "netflix", "bankofamerica", "chase", "wellsfargo", "baccredomatic", "banestes",
    "banestesnet", "magalu", "binance", "coinbase", "citrix", "docusign", "adobe",
    "linkedin", "twitter", "telegram", "whatsapp", "usps", "dhl", "fedex", "ups",
    "allegro", "saude", "portaldocliente", "mymaxis", "outlook", "office365",
    "icloud", "dropbox", "spotify", "steam", "roblox", "barclays", "hsbc", "santander"
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute exact Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class TyposquatEngine:
    """Engine for detecting zero-day typosquatting domain impersonations."""

    def __init__(self, brands: list[str] | None = None) -> None:
        self.protected_brands = brands or PROTECTED_BRANDS

    def check_url(self, url: str) -> TyposquatResult:
        """Check URL host and subdomains for zero-day typosquatting."""
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain.lower()
        domain = extracted.domain.lower()
        root_domain = f"{extracted.domain}.{extracted.suffix}".lower()

        # Tokens to inspect
        tokens = set(subdomain.split(".") + domain.split("-") + [domain])
        tokens = {t for t in tokens if len(t) >= 4}  # Filter out very short tokens

        best_match_brand = ""
        min_distance = 99
        best_sim_score = 0.0

        for token in tokens:
            for brand in self.protected_brands:
                # If exact match and domain is the brand, skip (legitimate)
                if token == brand and domain == brand:
                    continue

                dist = levenshtein_distance(token, brand)
                max_len = max(len(token), len(brand))
                sim_score = 1.0 - (dist / max_len)

                # Flag if edit distance is 1 or 2 on tokens of length >= 5
                if (dist == 1 or (dist == 2 and len(brand) >= 6)) and domain != brand:
                    if dist < min_distance:
                        min_distance = dist
                        best_match_brand = brand
                        best_sim_score = round(sim_score, 3)

        if best_match_brand:
            return TyposquatResult(
                is_typosquat=True,
                matched_brand=best_match_brand,
                edit_distance=min_distance,
                similarity_score=best_sim_score,
                reason=f"Zero-day typosquatting detected (impersonates '{best_match_brand}', edit distance={min_distance})"
            )

        return TyposquatResult(
            is_typosquat=False,
            matched_brand="",
            edit_distance=99,
            similarity_score=0.0,
            reason="No typosquatting detected"
        )
