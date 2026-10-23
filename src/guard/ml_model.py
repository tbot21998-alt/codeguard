from functools import lru_cache
from pathlib import Path
from collections import Counter
import sys

SOURCE_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "codeguard.joblib"
MODEL_PATH = SOURCE_MODEL_PATH if SOURCE_MODEL_PATH.is_file() else Path(sys.prefix) / "share/codeguard/models/codeguard.joblib"


@lru_cache(maxsize=1)
def load_model():
    if not MODEL_PATH.is_file():
        return None
    import joblib
    return joblib.load(MODEL_PATH)


DEFAULT_THRESHOLD = 0.85
DEFAULT_RULE_PRECISION = 0.85


def raw_probabilities(code):
    """Uncalibrated LightGBM probabilities, one per category."""
    model = load_model()
    if model is None:
        raise ValueError("Classifier unavailable; inspection cannot provide a model score")
    pipeline = model["pipeline"]
    features = transform_one(code)
    scores = {category: float(estimator.booster_.predict(features, num_threads=1)[0]) for category, estimator in zip(model["categories"], pipeline.named_steps["classifier"].estimators_, strict=True)}
    if not scores or any(not 0 <= value <= 1 for value in scores.values()):
        raise ValueError("Classifier produced invalid probabilities")
    return scores


def probabilities(code):
    """Calibrated probabilities (isotonic regression fitted on out-of-fold predictions) when the model has them."""
    scores = raw_probabilities(code)
    calibration = load_model().get("calibration")
    if not calibration:
        return scores
    import numpy as np
    return {category: float(np.interp(value, *calibration[category])) if category in calibration else value for category, value in scores.items()}


def model_info():
    return (load_model() or {}).get("info", {})


def block_threshold(category):
    return (load_model() or {}).get("thresholds", {}).get(category, DEFAULT_THRESHOLD)


def rule_precision(category):
    return (load_model() or {}).get("rule_precision", {}).get(category, DEFAULT_RULE_PRECISION)

@lru_cache(maxsize=1)
def feature_runtime():
    pipeline = load_model()['pipeline']
    branches = pipeline.named_steps['features'].transformer_list
    return [(branch.build_analyzer(), branch.vocabulary_, branch.idf_) for _, branch in branches[:2]], branches[2][1]


def transform_one(code):
    import numpy as np
    from scipy.sparse import csr_matrix
    branches, structural = feature_runtime()
    columns, weights = [], []
    offset = 0
    for analyzer, vocabulary, idf in branches:
        entries = [(vocabulary[token], count) for token, count in Counter(analyzer(code)).items() if token in vocabulary]
        if entries:
            indices = np.asarray([index for index, _ in entries])
            values = (1 + np.log([count for _, count in entries])) * idf[indices]
            values /= np.linalg.norm(values)
            columns.extend(indices + offset)
            weights.extend(values)
        offset += len(vocabulary)
    values = structural.transform([code])[0]
    columns.extend(range(offset, offset + len(values)))
    weights.extend(values)
    return csr_matrix((weights, ([0] * len(columns), columns)), shape=(1, offset + len(values)))
