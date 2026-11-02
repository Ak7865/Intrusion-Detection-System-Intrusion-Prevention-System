
from __future__ import annotations

import numpy as np
import pandas as pd

from ml.preprocessing.feature_schema import RUNTIME_FEATURES


# CICFlowMeter output column -> CIC-IDS2017 training column
EXTRACTOR_TO_MODEL_COLUMNS = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "down_up_ratio": "Down/Up Ratio",
}


class RuntimeFeatureAdapter:

    DURATION_CONVERSION_FACTOR = 1_000_000

    def transform(self, extracted: pd.DataFrame) -> pd.DataFrame:
        missing = [
            column
            for column in EXTRACTOR_TO_MODEL_COLUMNS
            if column not in extracted.columns
        ]

        if missing:
            raise ValueError(
                f"Missing CICFlowMeter features: {missing}"
            )

        adapted = extracted[
            list(EXTRACTOR_TO_MODEL_COLUMNS.keys())
        ].rename(columns=EXTRACTOR_TO_MODEL_COLUMNS).copy()

        adapted["Flow Duration"] *= self.DURATION_CONVERSION_FACTOR

        adapted = adapted[RUNTIME_FEATURES]

        adapted = adapted.apply(
            pd.to_numeric,
            errors="coerce",
        )

        values = adapted.to_numpy(dtype=np.float64)

        if not np.isfinite(values).all():
            raise ValueError(
                "Runtime features contain NaN or infinite values"
            )

        if (values < 0).any():
            raise ValueError(
                "Runtime features contain negative values"
            )

        return adapted.astype(np.float32)
