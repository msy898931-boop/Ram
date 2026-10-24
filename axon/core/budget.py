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
                f"budget cap ${self.limit_usd:.4f} exceeded "
                f"(spent ${self.spent_usd:.4f}, next ${next_estimate:.4f})"
            )
