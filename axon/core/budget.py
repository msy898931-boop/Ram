# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Cost control — hard budget caps per agent/run.

AXON Observe's enforcement primitive. When a run exceeds its cap the
runtime stops the agent before the next model call, so a runaway loop
cannot drain a company's token budget.
"""

from __future__ import annotations

from dataclasses import dataclass


class BudgetExceeded(Exception):
    pass


def format_usd(amount: float) -> str:
    """Money with enough precision to be honest about small amounts.

    A flat `:.4f` renders a $0.000001 cap as `$0.0000`, so the message reads
    "budget cap $0.0000 exceeded" — which looks like a broken cap rather than
    a tight one, and is the first thing a visitor to the demo sees. Four
    decimals where that suffices, six where it does not.
    """
    if amount == 0:
        return "$0.00"
    if abs(amount) < 0.01:
        return f"${amount:.6f}"
    return f"${amount:.4f}"


@dataclass
class Budget:
    limit_usd: float
    spent_usd: float = 0.0

    def charge(self, amount: float) -> None:
        self.spent_usd += amount

    @property
    def remaining(self) -> float:
        return max(0.0, self.limit_usd - self.spent_usd)

    def check(self, next_estimate: float = 0.0) -> None:
        if self.spent_usd + next_estimate > self.limit_usd:
            raise BudgetExceeded(
                f"budget cap {format_usd(self.limit_usd)} exceeded "
                f"(spent {format_usd(self.spent_usd)}, "
                f"next {format_usd(next_estimate)})"
            )
