# Multiclass Model Selection Report

**Dataset:** CIC-IDS2017
**Training records:** 2,211,941
**Test records:** 552,985
**Features:** 11
**Classes:** 8

## 1. Overall Performance Comparison

| Metric | Random Forest | XGBoost |
|---|---:|---:|
| Accuracy (%) | 98.4817 | 99.8127 |
| Macro precision (%) | 75.5040 | 98.6052 |
| Macro recall (%) | 97.7694 | 76.5487 |
| Macro F1 (%) | 77.4737 | 81.4905 |
| Weighted F1 (%) | 99.0597 | 99.7776 |
| Training time (s) | 164.8609 | 313.5977 |
| Standardized inference time (s) | 3.2103 | 7.0073 |
| Standardized latency (ms/flow) | 0.0058 | 0.0127 |
| Standardized throughput (flows/s) | 172252.4222 | 78915.3038 |

## 2. Per-Class Performance

| Class | Support | RF Precision | RF Recall | RF F1 | XGB Precision | XGB Recall | XGB F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Botnet | 378 | 7.23% | 98.68% | 13.48% | 98.03% | 39.42% | 56.23% |
| Brute Force | 2435 | 98.46% | 99.96% | 99.21% | 99.92% | 99.96% | 99.94% |
| DoS/DDoS | 65901 | 99.38% | 99.88% | 99.63% | 99.72% | 99.79% | 99.75% |
| Infiltration | 8 | 87.50% | 87.50% | 87.50% | 100.00% | 62.50% | 76.92% |
| Normal | 452308 | 99.98% | 98.17% | 99.07% | 99.84% | 99.94% | 99.89% |
| OTHER_RARE | 2 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| PortScan | 31547 | 99.64% | 99.94% | 99.79% | 99.68% | 99.95% | 99.81% |
| Web Attack | 406 | 11.83% | 98.03% | 21.12% | 91.67% | 10.84% | 19.38% |

## 3. Key Findings

- XGBoost achieved higher accuracy, macro precision, macro F1, and weighted F1.
- Random Forest achieved higher macro recall.
- Random Forest had higher standardized inference throughput and lower standardized latency.
- Random Forest showed low precision for Botnet and Web Attack.
- XGBoost showed low recall for Botnet and Web Attack.
- Infiltration and OTHER_RARE have very small test supports.

## 4. Benchmark Methodology

- Benchmark: Standardized Multiclass Inference Benchmark V1
- Chunk size: 50,000
- Number of chunks: 12
- Warm-up records per model: 1,000
- Prediction method: predict_proba followed by argmax for multiclass classification.
- Timing scope: Prediction computation and argmax only. CSV reading, model loading, warm-up, and garbage collection are excluded.
- Only one measured benchmark pass was performed.

## 5. Limitations

- The dataset is highly class-imbalanced.
- Infiltration has only 8 test records.
- OTHER_RARE has only 2 test records.
- Minority-class metrics are not reliable estimates of generalized performance at these support levels.
- The standardized inference benchmark contains one measured pass.
- Benchmark results measure prediction computation and argmax, not complete end-to-end IPS processing latency.
- Results are specific to the selected CIC-IDS2017 split and the 11 deployment features.

## 6. Model Selection Recommendation

**Status:** `PROVISIONAL_NO_UNCONDITIONAL_WINNER`

- **Random Forest:** Consider when inference throughput and attack-family recall are priorities, but investigate its false positives.
- **XGBoost:** Consider when precision and overall classification performance are priorities, but investigate missed Botnet and Web Attack samples.

Do not finalize the Phase 1 multiclass model yet. Evaluate class-specific error costs, improve minority-class performance, and validate using controlled lab traffic.

## 7. Conclusion

The experiment demonstrates a trade-off between classification performance and inference efficiency. XGBoost provides stronger overall accuracy and precision, while Random Forest provides higher macro recall and substantially higher inference throughput. However, both models exhibit weaknesses on minority attack classes. A final deployment decision requires further class-specific evaluation and validation against controlled lab traffic.
