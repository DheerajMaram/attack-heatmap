# Sample ATT&CK Coverage Gap Report

This sample illustrates the kind of output the pipeline produces after a successful run with live feed data and local Sigma coverage. Actual results will vary based on the active feed window, configured enrichments, and the rules present in `sigma/rules/`.

> Example snapshot only. Do not treat these counts as fixed project metrics.

## Summary

| Metric | Count |
|--------|-------|
| Active techniques (observed in feeds) | 18 |
| Covered by Sigma rules | 7 |
| **Gaps (active, no detection)** | **11** |
| Coverage ratio | 38.9% |

## Critical Gaps — Active Threats with No Sigma Detection

| Rank | Technique ID | TIE Score | ATT&CK v18 Analytics |
|------|-------------|-----------|----------------------|
| 1 | T1566.001 | 0.82 | AN0350 |
| 2 | T1059.001 | 0.78 | AN0258 |
| 3 | T1071.001 | 0.74 | AN0402 |
| 4 | T1105 | 0.69 | AN0219 |
| 5 | T1027 | 0.61 | AN0177 |

## Active Techniques with Sigma Coverage

| Technique ID |
|-------------|
| T1003 |
| T1047 |
| T1053.005 |
| T1055 |
| T1078 |
| T1486 |
| T1562.001 |
