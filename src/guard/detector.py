from dataclasses import replace

from guard.lang_detect import detect_language
from guard.mitre import mitre_for, techniques_for
from guard.ml_model import block_threshold, probabilities, rule_precision
from guard.schema import MAX_CODE_LENGTH, MAX_CODE_LINES, Inspection, Verdict
from guard.static_rules import analyze

# Policy weights (expert judgement, not learned): how harmful a confirmed hit in this category is.
SEVERITY_FLOOR = {
    "destructive_command": 0.90, "data_exfiltration": 0.90, "persistence_or_privesc": 0.90,
    "secret_access": 0.85, "obfuscated_execution": 0.85, "ssrf_network_exfil": 0.80,
    "ai_targeted_instructions": 0.75, "dependency_risk": 0.70, "resource_exhaustion": 0.65,
}


def static_scores(findings, scores):
    """Scores for a static-rule block.

    risk       = severity floor of the worst flagged category, raised toward 1 by the calibrated model probability.
    confidence = P(block is correct) = noisy-OR of two independent signals:
                 the measured precision of the rule family and the calibrated model probability for that category.
    Returns (risk, confidence, breakdown).
    """
    categories = sorted({item.category for item in findings})
    worst = max(categories, key=lambda c: SEVERITY_FLOOR.get(c, 0.7))
    floor = SEVERITY_FLOOR.get(worst, 0.7)
    model = max((scores.get(category, 0.0) for category in categories), default=0.0)
    precision = max(rule_precision(category) for category in categories)
    risk = floor + (1 - floor) * model
    confidence = min(0.99, 1 - (1 - precision) * (1 - model))
    return round(risk, 4), round(confidence, 4), {
        "decision": "static_rule", "worst_category": worst, "severity_floor": floor,
        "model_probability": round(model, 4) if scores else None, "rule_precision": round(precision, 4),
        "risk_formula": "severity_floor + (1 - severity_floor) * model_probability",
        "confidence_formula": "1 - (1 - rule_precision) * (1 - model_probability)",
    }


def evaluate(code, *, language=None, use_model=True, fast=False):
    return inspect_code(code, language=language, use_model=use_model, fast=fast).verdict


def inspect_code(code, *, language=None, use_model=True, fast=False):
    """Inspect source text.

    fast=True skips model inference when a static rule already decides the block (the verdict, categories and
    lines are identical; only the model-derived part of the scores is omitted). Used by latency-sensitive CLI hooks.
    """
    if not isinstance(code, str) or not code.strip():
        raise ValueError("code must be a nonempty string")
    if len(code) > MAX_CODE_LENGTH:
        raise ValueError(f"code must not exceed {MAX_CODE_LENGTH} characters")
    if code.count("\n") + 1 > MAX_CODE_LINES:
        raise ValueError(f"code must not exceed {MAX_CODE_LINES} lines")
    detected = language or detect_language(code)
    static = analyze(code, detected)
    skip_model = fast and bool(static)
    scores = probabilities(code) if use_model and not skip_model else {}
    findings = [replace(item, score=scores.get(item.category), mitre=mitre_for(item.category)) for item in static]
    if findings:
        if scores or skip_model:
            risk, confidence, breakdown = static_scores(findings, scores)
            basis = "rule_precision_noisy_or_calibrated_model" if scores else "rule_precision_only_model_skipped"
        else:
            risk = confidence = None
            breakdown = {"decision": "static_rule", "note": "model disabled"}
            basis = "model_disabled_score_unavailable"
        verdict = Verdict(
            verdict="block", risk_score=risk, confidence_score=confidence,
            categories=sorted({item.category for item in findings}), code_language=detected,
            reason=" ".join(dict.fromkeys(item.reason for item in findings)),
            vulnerable_lines=sorted({item.line for item in findings}),
        )
        return Inspection(verdict, findings, confidence, basis, techniques_for(verdict.categories), breakdown)
    suspicious = {category: score for category, score in scores.items() if score >= block_threshold(category)}
    if suspicious:
        worst = max(suspicious, key=lambda c: (SEVERITY_FLOOR.get(c, 0.7), suspicious[c]))
        floor = SEVERITY_FLOOR.get(worst, 0.7)
        top = max(suspicious.values())
        risk = round(floor + (1 - floor) * top, 4)
        confidence = round(min(0.99, top), 4)
        verdict = Verdict(
            verdict="block", risk_score=risk, confidence_score=confidence,
            categories=sorted(suspicious), code_language=detected,
            reason="Local statistical model flags a high-confidence threat pattern; review before execution.",
            vulnerable_lines=[],
        )
        breakdown = {
            "decision": "model_only", "worst_category": worst, "severity_floor": floor, "model_probability": round(top, 4),
            "threshold": block_threshold(worst),
            "risk_formula": "severity_floor + (1 - severity_floor) * model_probability",
            "confidence_formula": "calibrated model probability",
        }
        return Inspection(verdict, [], confidence, "calibrated_model_probability", techniques_for(verdict.categories), breakdown)
    risk = max(scores.values()) if scores else None
    benign = 1.0
    for value in scores.values():
        benign *= 1 - value
    confidence = round(benign, 4) if scores else None
    verdict = Verdict(
        verdict="allow", risk_score=risk, confidence_score=confidence,
        categories=[], code_language=detected,
        reason="No configured static rule or high-confidence local model signal matched. This is not a proof of safety.",
        vulnerable_lines=[],
    )
    breakdown = {"decision": "allow", "model_probability": round(risk, 4) if scores else None,
                 "risk_formula": "max calibrated category probability",
                 "confidence_formula": "product over categories of (1 - calibrated probability)"} if scores else {"decision": "allow", "note": "model disabled"}
    return Inspection(verdict, [], confidence, "calibrated_probability_no_category_applies" if scores else "model_disabled_score_unavailable", [], breakdown)
