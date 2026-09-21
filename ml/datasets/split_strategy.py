"""Dataset splitting strategies for PhishGuard evaluation pipeline.

Implements 4 distinct dataset split strategies to prevent data leakage and simulate real deployment scenarios:

1. Random Split: Standard stratified 70/15/15 train/val/test split.
2. Domain-Disjoint Split: Enforces strict domain isolation — NO domain in train set appears in val or test sets.
3. Temporal Split: Sorts samples by collection date — older data for train, newest for test (evaluates model staleness).
4. Unseen-Domain Split: Dedicated held-out domain evaluation set for zero-day generalization assessment.

IMPORTANT RESEARCH DESIGN PRINCIPLE:
    - Data leakage between training and evaluation splits invalidates academic claims.
    - Domain-disjoint and temporal splits are enforced programmatically.
"""

from __future__ import annotations

import random
from collections import defaultdict
from datetime import datetime
from typing import Any

from backend.app.core.logging import get_logger

logger = get_logger(__name__)


class DatasetSplitter:
    """Provides methods for dataset partitioning with zero leakage.

    Usage:
        splitter = DatasetSplitter(seed=42)
        train, val, test = splitter.domain_disjoint_split(samples)
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        random.seed(seed)

    def random_split(
        self, samples: list[dict[str, Any]], train_ratio: float = 0.70, val_ratio: float = 0.15
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Perform stratified random split (70/15/15).

        Args:
            samples: List of sample dictionaries with 'label'.
            train_ratio: Ratio for training set.
            val_ratio: Ratio for validation set.

        Returns:
            Tuple of (train_samples, val_samples, test_samples).
        """
        benign = [s for s in samples if s.get("label") == "benign"]
        phishing = [s for s in samples if s.get("label") == "phishing"]

        random.shuffle(benign)
        random.shuffle(phishing)

        def _split_group(grp: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
            n = len(grp)
            n_train = int(n * train_ratio)
            n_val = int(n * val_ratio)
            return grp[:n_train], grp[n_train:n_train + n_val], grp[n_train + n_val:]

        b_train, b_val, b_test = _split_group(benign)
        p_train, p_val, p_test = _split_group(phishing)

        train = b_train + p_train
        val = b_val + p_val
        test = b_test + p_test

        random.shuffle(train)
        random.shuffle(val)
        random.shuffle(test)

        self._annotate_splits(train, val, test)
        logger.info(f"Random Split: train={len(train)}, val={len(val)}, test={len(test)}")
        return train, val, test

    def domain_disjoint_split(
        self, samples: list[dict[str, Any]], train_ratio: float = 0.70, val_ratio: float = 0.15
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Perform domain-disjoint split ensuring zero domain leakage across splits.

        Args:
            samples: List of sample dictionaries with 'domain' and 'label'.
            train_ratio: Target train ratio.
            val_ratio: Target validation ratio.

        Returns:
            Tuple of (train_samples, val_samples, test_samples).
        """
        # Group samples by domain
        domain_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for s in samples:
            dom = s.get("domain") or "unknown_domain"
            domain_groups[dom].append(s)

        domains = list(domain_groups.keys())
        random.shuffle(domains)

        total_samples = len(samples)
        target_train = int(total_samples * train_ratio)
        target_val = int(total_samples * val_ratio)

        train_domains, val_domains, test_domains = set(), set(), set()
        current_train_count, current_val_count = 0, 0

        for dom in domains:
            count = len(domain_groups[dom])
            if current_train_count < target_train:
                train_domains.add(dom)
                current_train_count += count
            elif current_val_count < target_val:
                val_domains.add(dom)
                current_val_count += count
            else:
                test_domains.add(dom)

        train = [s for dom in train_domains for s in domain_groups[dom]]
        val = [s for dom in val_domains for s in domain_groups[dom]]
        test = [s for dom in test_domains for s in domain_groups[dom]]

        random.shuffle(train)
        random.shuffle(val)
        random.shuffle(test)

        # Assert ZERO domain leakage
        train_dom_set = set(s.get("domain") for s in train)
        val_dom_set = set(s.get("domain") for s in val)
        test_dom_set = set(s.get("domain") for s in test)

        assert train_dom_set.isdisjoint(val_dom_set), "Domain leakage between train and val!"
        assert train_dom_set.isdisjoint(test_dom_set), "Domain leakage between train and test!"
        assert val_dom_set.isdisjoint(test_dom_set), "Domain leakage between val and test!"

        self._annotate_splits(train, val, test)
        logger.info(f"Domain-Disjoint Split: train={len(train)}, val={len(val)}, test={len(test)} (Zero Domain Leakage)")
        return train, val, test

    def temporal_split(
        self, samples: list[dict[str, Any]], train_ratio: float = 0.70, val_ratio: float = 0.15
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Perform temporal split by sorting samples chronologically.

        Older samples -> train, middle -> val, newest -> test.

        Args:
            samples: List of sample dictionaries with 'collection_date'.
            train_ratio: Target train ratio.
            val_ratio: Target validation ratio.

        Returns:
            Tuple of (train_samples, val_samples, test_samples).
        """
        def _parse_date(s: dict[str, Any]) -> datetime:
            dt_str = s.get("collection_date") or ""
            try:
                return datetime.fromisoformat(dt_str)
            except Exception:
                return datetime.min

        sorted_samples = sorted(samples, key=_parse_date)

        n = len(sorted_samples)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train = sorted_samples[:n_train]
        val = sorted_samples[n_train:n_train + n_val]
        test = sorted_samples[n_train + n_val:]

        self._annotate_splits(train, val, test)
        logger.info(f"Temporal Split: train={len(train)} (oldest), val={len(val)}, test={len(test)} (newest)")
        return train, val, test

    def unseen_domain_split(
        self, samples: list[dict[str, Any]], held_out_domains: list[str]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Partition dataset into training set and dedicated unseen-domain evaluation set.

        Args:
            samples: Full list of samples.
            held_out_domains: List of domain strings to hold out for evaluation.

        Returns:
            Tuple of (train_samples, unseen_test_samples).
        """
        held_out_set = set(d.lower() for d in held_out_domains)
        train = [s for s in samples if (s.get("domain") or "").lower() not in held_out_set]
        unseen_test = [s for s in samples if (s.get("domain") or "").lower() in held_out_set]

        for s in train:
            s["split"] = "train"
        for s in unseen_test:
            s["split"] = "unseen_test"

        logger.info(f"Unseen-Domain Split: train={len(train)}, unseen_test={len(unseen_test)} across {len(held_out_domains)} held-out domains")
        return train, unseen_test

    @staticmethod
    def _annotate_splits(
        train: list[dict[str, Any]], val: list[dict[str, Any]], test: list[dict[str, Any]]
    ) -> None:
        """Annotate 'split' key in sample dictionaries."""
        for s in train:
            s["split"] = "train"
        for s in val:
            s["split"] = "val"
        for s in test:
            s["split"] = "test"
