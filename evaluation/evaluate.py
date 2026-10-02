"""Runs the firewall over a test set and computes metrics."""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from firewall.pipeline import FirewallPipeline
from evaluation.metrics import (
    compute_metrics,
    per_attack_breakdown,
    per_source_breakdown,
    false_positives,
    false_negatives
)

REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def load_test_set(path: Path):
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples

def run_evaluation(test_file: Path, use_llm: bool = True, model: str = "llama3.2", limit: int | None = None, verbose: bool = True):
    samples = load_test_set(test_file)
    if limit:
        samples = samples[:limit]

    pipeline = FirewallPipeline(llm_model=model, use_llm=use_llm)

    results = []
    start = time.perf_counter()

    for i, sample in enumerate(samples, 1):
        try:
            decision = pipeline.process(sample["content"], source=sample["source"])
            predicted_label = "malicious" if decision.decision in ("block", "sanitize") else "benign"
            predicted_attack = decision.attack_type
            latency = decision.latency_ms
            error = None
        except Exception as e:
            predicted_label = "benign"
            predicted_attack = None
            latency = 0.0
            error = str(e)

        results.append({
            "id": sample["id"],
            "source": sample["source"],
            "true_label": sample["label"],
            "true_attack": sample["attack_type"],
            "predicted_label": predicted_label,
            "predicted_attack": predicted_attack,
            "confidence": decision.confidence if not error else 0.0,
            "descision": decision.decision if not error else "error",
            "latency_ms": latency,
            "error": error,
            "content_preview": sample["content"][:120]
        })

        if verbose and i % 10 == 0:
            print(f" Processed {i}/{len(samples)}")

    total_time = time.perf_counter() - start

    y_true = [r["true_label"] for r in results]
    y_pred = [r["predicted_label"] for r in results]

    report = {
        "config": {
            "test_file": str(test_file),
            "use_llm": use_llm,
            "model": model if use_llm else None,
            "sample_count": len(samples)
        },
        "overall": compute_metrics(y_true, y_pred),
        "per_attack": per_attack_breakdown(results),
        "per_source": per_source_breakdown(results),
        "false_positives": false_positives(results),
        "false_negatives": false_negatives(results),
        "timing": {
            "total_seconds": round(total_time, 2),
            "avg_latency_ms": round(sum(r["latency_ms"] for r in results) / max(len(results), 1), 1)    
        },
        "raw_results": results
    }
    return report

def write_markdown_report(report: dict, path: Path):
    o = report["overall"]
    lines = []
    lines.append("# Firewall Evaluation Report\n")
    lines.append(f"**Test file:** {report['config']['test_file']} ")
    lines.append(f"**Samples:** {report['config']['sample_count']} ")
    lines.append(f"**LLM enabled:** {report['config']['use_llm']} ")
    lines.append(f"**Model:** {report['config']['model'] or 'n/a'} ")
    lines.append(f"**Avg latency:** {report['timing']['avg_latency_ms']} ms \n")

    lines.append("## Overall Metrics\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Precision | {o['precision']:.3f} |")
    lines.append(f"| Recall | {o['recall']:.3f} |")
    lines.append(f"| F1 | {o['f1']:.3f} |")
    lines.append(f"| Accuracy | {o['accuracy']:.3f} |")
    lines.append(f"| False Positive Rate | {o['false_positive_rate']:.3f} |")
    lines.append(f"| False Negative Rate | {o['false_negative_rate']:.3f} |")
    lines.append(f"| TP / FP / TN / FN | {o['tp']} / {o['fp']} / {o['tn']} / {o['fn']} |\n")

    lines.append("## Per-Attack Detection Rate\n")
    lines.append("| Attack Type | Detected / Total | Rate |")
    lines.append("|---|---|---|")
    for attack, stats in sorted(report["per_attack"].items()):
        lines.append(f"| {attack} | {stats['detected']} / {stats['total']} | {stats['detection_rate']:.3f} |")
    lines.append("")

    lines.append("## Per-Source Accuracy\n")
    lines.append("| Source | Correct / Total | Accuracy |")
    lines.append("|---|---|---|")
    for source, stats in sorted(report["per_source"].items()):
        lines.append(f"| {source} | {stats['correct']} / {stats['total']} | {stats['accuracy']:.3f} |")
    lines.append("")

    if report["false_positives"]:
        lines.append(f"## False Positives ({len(report['false_positives'])})\n")
        for fp in report["false_positives"][:10]:
            lines.append(f"- {fp['id']} ({fp['source']}): {fp['content_preview']}")
        lines.append("")

    if report["false_negatives"]:
        lines.append(f"## False Negatives ({len(report['false_negatives'])})\n")
        for fn in report["false_negatives"][:10]:
            lines.append(f"- {fn['id']} ({fn['true_attack']}): {fn['content_preview']}")
        lines.append("")

    path.write_text("\n".join(lines))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", default="data/test_sets/test_full.jsonl")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM detector (faster)")
    parser.add_argument("--model", default="llama3.2")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--tag", default="run", help="Name for output files")
    args = parser.parse_args()

    print(f"Running evaluation on {args.test} (LLM={'off' if args.no_llm else 'on'})")
    report = run_evaluation(
        Path(args.test),
        use_llm=not args.no_llm,
        model=args.model,
        limit=args.limit
    )

    json_path = REPORTS_DIR / f"{args.tag}.json"
    md_path = REPORTS_DIR / f"{args.tag}.md"

    json_path.write_text(json.dumps(report, indent=2))
    write_markdown_report(report, md_path)

    o = report["overall"]
    print("\n==== Results ====")
    print(f"Precision: {o['precision']:.3f}")
    print(f"Recall: {o['recall']:.3f}")
    print(f"F1: {o['f1']:.3f}")
    print(f"Accuracy: {o['accuracy']:.3f}")
    print(f"FPR: {o['false_positive_rate']:.3f}")
    print(f"FNR: {o['false_negative_rate']:.3f}")
    print(f"\nSaved: {json_path}")
    print(f"Saved: {md_path}")

if __name__ == "__main__":
    main()