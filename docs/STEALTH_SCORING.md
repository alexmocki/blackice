# Stealth scoring

We rank strategies by a weighted score of:
- normalized impact
- normalized stealth (fewer detections / bad rules is better)
- efficiency (fewer steps is better)

Definitions:
- det = count(bad_rules)  (dict: sum values; list: len)
- stealth_n = 1 / (1 + det)
- impact_n = clamp(impact / impact_cap, 0..1)
- eff_n = 1 - clamp(step_s / max_steps, 0..1)

Score:
total = (0.55*impact_n + 0.35*stealth_n + 0.10*eff_n) * (0.90 ** det)
