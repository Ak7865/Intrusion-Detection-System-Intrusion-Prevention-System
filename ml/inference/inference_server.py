import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml.inference.runtime_feature_adapter import RuntimeFeatureAdapter

from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

# --------------------------------------------------
# Configuration
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "random_forest_binary_pilot.joblib"
)

HOST = "192.168.56.1"
PORT = 8765

MODEL_VERSION = "binary-rf-pilot-v1.0"
MAX_REQUEST_SIZE = 1_000_000

SENSOR_ID = "node-a"

PREDICTION_LOG =(
    PROJECT_ROOT
    / "logs"
    / "ml-predictions-node-a.jsonl"
)

PREDICTION_LOG.parent.mkdir(
    parents=True,
    exist_ok=True
)

PREDICTION_LOG_LOCK = Lock()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("IPS-Inference")


# --------------------------------------------------
# Load model
# --------------------------------------------------

if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

logger.info("Loading Random Forest model...")

model = joblib.load(MODEL_PATH)
adapter = RuntimeFeatureAdapter()

if model.n_features_in_ != 11:
    raise RuntimeError(
        f"Expected 11 model features, found {model.n_features_in_}"
    )

if not np.array_equal(model.classes_, np.array([0, 1])):
    raise RuntimeError(
        f"Unexpected model classes: {model.classes_}"
    )

logger.info("Model loaded successfully.")
logger.info("Model features: %s", model.n_features_in_)
logger.info("Model classes: %s", model.classes_)


# --------------------------------------------------
# HTTP response helper
# --------------------------------------------------

def send_json(handler, status_code, payload):

    response = json.dumps(payload).encode("utf-8")

    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(response)))
    handler.end_headers()

    handler.wfile.write(response)

def save_prediction(record:dict)->None:
    """Save prediction record to log file in JSON Lines format."""
    with PREDICTION_LOG_LOCK:
        with PREDICTION_LOG.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                ) + "\n"
            )

            file.flush()  # Ensure data is written to disk

# --------------------------------------------------
# HTTP request handler
# --------------------------------------------------

class InferenceHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path != "/health":
            send_json(
                self,
                404,
                {"error": "Endpoint not found"},
            )
            return

        send_json(
            self,
            200,
            {
                "status": "healthy",
                "service": "IPS ML Inference",
                "model": MODEL_VERSION,
                "model_type": type(model).__name__,
                "features": model.n_features_in_,
                "classes": [int(value) for value in model.classes_],
            },
        )

    def do_POST(self):

        if self.path != "/predict":
            send_json(
                self,
                404,
                {"error": "Endpoint not found"},
            )
            return

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )

            if content_length <= 0:
                send_json(
                    self,
                    400,
                    {"error": "Request body is empty"},
                )
                return

            if content_length > MAX_REQUEST_SIZE:
                send_json(
                    self,
                    413,
                    {"error": "Request body too large"},
                )
                return

            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body)

            if not isinstance(payload, dict):
                raise ValueError(
                    "Request must contain a JSON object"
                )

            flow = payload.get("flow", payload)

            if not isinstance(flow, dict):
                raise ValueError(
                    "'flow' must be a JSON object"
                )

            # Adapt extracted CICFlowMeter features.
            extracted = pd.DataFrame([flow])

            features = adapter.transform(extracted)

            # Predict using the existing supervised model.
            X = features.to_numpy(dtype=np.float32)

            prediction = int(model.predict(X)[0])
            probabilities = model.predict_proba(X)[0]

            model_input_record ={
                column: float(value)
                for column, value in zip(features.columns, X[0])
            }

            probability_map = {
                int(class_id): float(probability)
                for class_id, probability
                in zip(model.classes_, probabilities)
            }

            label = (
                "ATTACK"
                if prediction == 1
                else "BENIGN"
            )

            prediction_id = str(uuid4())

            prediction_timestamp =(
                datetime.now(timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )

            prediction_record = {
                "prediction_id": prediction_id,
                "timestamp": prediction_timestamp,
                "sensor_id": SENSOR_ID,
                "model_version": MODEL_VERSION,
                "prediction": prediction,
                "prediction_label": label,
                "benign_probability": probability_map[0],
                "attack_probability": probability_map[1],
                "flow": {
                    "src_ip": flow.get("src_ip"),
                    "dst_ip": flow.get("dst_ip"),
                    "src_port": flow.get("src_port"),
                    "dst_port": flow.get("dst_port"),
                    "protocol": flow.get("protocol"),
                },
                "raw_features": {
                    key: (
                        value.item()
                        if isinstance(value, np.generic)
                        else value
                    )
                    for key, value in flow.items()

                },
                "model_input": model_input_record,
            }

            save_prediction(prediction_record)

            result = {
                "status": "success",
                "model": MODEL_VERSION,
                "prediction_id": prediction_id,
                "timestamp": prediction_timestamp,
                "sensor_id": SENSOR_ID,
                "model_version": MODEL_VERSION,
                "prediction": prediction,
                "prediction_label": label,
                "benign_probability": probability_map[0],
                "attack_probability": probability_map[1],
                "flow": prediction_record["flow"],
            }

            logger.info(
                "Prediction: %s | %s:%s -> %s:%s",
                label,
                flow.get("src_ip"),
                flow.get("src_port"),
                flow.get("dst_ip"),
                flow.get("dst_port"),
            )

            send_json(self, 200, result)

        except (ValueError, TypeError, KeyError) as exc:

            logger.warning("Invalid prediction request: %s", exc)

            send_json(
                self,
                400,
                {
                    "status": "error",
                    "error": str(exc),
                },
            )

        except json.JSONDecodeError:

            send_json(
                self,
                400,
                {
                    "status": "error",
                    "error": "Invalid JSON",
                },
            )

        except Exception:

            logger.exception("Inference failed")

            send_json(
                self,
                500,
                {
                    "status": "error",
                    "error": "Internal inference error",
                },
            )

    def log_message(self, format, *args):
        logger.info(format % args)


# --------------------------------------------------
# Start server
# --------------------------------------------------

def main():

    server = ThreadingHTTPServer(
        (HOST, PORT),
        InferenceHandler,
    )

    logger.info(
        "Inference server listening at http://%s:%s",
        HOST,
        PORT,
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        logger.info("Shutting down inference server...")

    finally:
        server.server_close()


if __name__ == "__main__":
    main()

