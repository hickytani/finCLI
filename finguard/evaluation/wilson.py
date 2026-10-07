"""FG-401 Exact Wilson Score 95% Confidence Interval Calculator.

Formula:
p_hat = successes / n
z = 1.95996  (for 95% confidence interval)
center = (p_hat + z^2 / (2 * n)) / (1 + z^2 / n)
spread = (z / (1 + z^2 / n)) * sqrt((p_hat * (1 - p_hat) / n) + (z^2 / (4 * n^2)))
lower = max(0.0, center - spread)
upper = min(1.0, center + spread)
"""

from __future__ import annotations

import math


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> tuple[float, float]:
    """Calculate the Wilson score confidence interval for a binomial proportion.

    Handles zero trials, zero successes, all successes, and small sample sizes.
    Returns (lower_bound, upper_bound) bounded between 0.0 and 1.0.
    """
    if trials <= 0:
        return (0.0, 0.0)

    successes = max(0, min(successes, trials))

    # Standard normal z-scores for common confidence levels
    z_map = {
        0.90: 1.64485,
        0.95: 1.95996,
        0.99: 2.57583,
    }
    z = z_map.get(confidence, 1.95996)

    n = float(trials)
    p_hat = successes / n
    z2 = z * z

    denominator = 1.0 + (z2 / n)
    center = (p_hat + (z2 / (2.0 * n))) / denominator

    variance_term = (p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n))
    spread = (z / denominator) * math.sqrt(max(0.0, variance_term))

    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)

    return (round(lower, 6), round(upper, 6))
