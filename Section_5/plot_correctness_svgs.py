#!/usr/bin/env python3
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCORES_DIR = ROOT / "Section 5" / "scores"
OUT_DIR = ROOT / "assets"

MODEL_FILES = {
    "GPT": "gpt_correctness.csv",
    "Claude": "claude_correctness.csv",
    "Llama": "llama_correctness.csv",
    "Gemini": "gemini_correctness.csv",
    "Qwen": "qwen_correctness.csv",
}

COLORS = {
    "GPT": "#d1495b",
    "Claude": "#00798c",
    "Llama": "#edae49",
    "Gemini": "#2a9d8f",
    "Qwen": "#6a4c93",
}


def read_cve_means(csv_path: Path):
    cve_means = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = [x for x in reader.fieldnames if x != "CVE"]
        for row in reader:
            vals = []
            for field in fields:
                raw = (row.get(field) or "").strip()
                if not raw:
                    continue
                try:
                    vals.append(float(raw))
                except ValueError:
                    continue
            if vals:
                cve_means.append(sum(vals) / len(vals))
    return cve_means


def esc(text: str):
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_model_mean_bar_chart(data):
    width, height = 980, 520
    margin_l, margin_r, margin_t, margin_b = 70, 30, 60, 70
    plot_w = width - margin_l - margin_r
    plot_h = height - margin_t - margin_b
    y_min, y_max = 1.0, 5.0

    def y(v):
        return margin_t + (y_max - v) / (y_max - y_min) * plot_h

    bar_gap = 20
    bar_w = (plot_w - bar_gap * (len(data) + 1)) / len(data)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="490" y="32" text-anchor="middle" font-family="Arial" font-size="20" fill="#222">Mean Correctness Score by Model</text>',
    ]

    for tick in [1, 2, 3, 4, 5]:
        yy = y(tick)
        parts.append(f'<line x1="{margin_l}" y1="{yy:.2f}" x2="{width - margin_r}" y2="{yy:.2f}" stroke="#e6e6e6" stroke-width="1"/>')
        parts.append(f'<text x="{margin_l - 10}" y="{yy + 4:.2f}" text-anchor="end" font-family="Arial" font-size="12" fill="#444">{tick}</text>')

    parts.append(f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{height - margin_b}" stroke="#222" stroke-width="1.5"/>')
    parts.append(f'<line x1="{margin_l}" y1="{height - margin_b}" x2="{width - margin_r}" y2="{height - margin_b}" stroke="#222" stroke-width="1.5"/>')

    for i, (model, val) in enumerate(data):
        x = margin_l + bar_gap + i * (bar_w + bar_gap)
        y_top = y(val)
        h = (height - margin_b) - y_top
        color = COLORS[model]
        parts.append(f'<rect x="{x:.2f}" y="{y_top:.2f}" width="{bar_w:.2f}" height="{h:.2f}" fill="{color}" rx="4"/>')
        parts.append(f'<text x="{x + bar_w / 2:.2f}" y="{y_top - 8:.2f}" text-anchor="middle" font-family="Arial" font-size="13" fill="#222">{val:.2f}</text>')
        parts.append(f'<text x="{x + bar_w / 2:.2f}" y="{height - margin_b + 22:.2f}" text-anchor="middle" font-family="Arial" font-size="13" fill="#222">{esc(model)}</text>')

    parts.append(f'<text x="{margin_l - 45}" y="{margin_t - 8}" font-family="Arial" font-size="12" fill="#333">Score</text>')
    parts.append("</svg>")
    (OUT_DIR / "correctness_model_mean.svg").write_text("\n".join(parts), encoding="utf-8")


def write_sorted_cve_lines(model_to_scores):
    width, height = 1080, 560
    margin_l, margin_r, margin_t, margin_b = 80, 30, 60, 75
    plot_w = width - margin_l - margin_r
    plot_h = height - margin_t - margin_b
    y_min, y_max = 1.0, 5.0
    max_len = max(len(v) for v in model_to_scores.values())

    def y(v):
        return margin_t + (y_max - v) / (y_max - y_min) * plot_h

    def x(i):
        if max_len <= 1:
            return margin_l
        return margin_l + (i / (max_len - 1)) * plot_w

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="540" y="32" text-anchor="middle" font-family="Arial" font-size="20" fill="#222">Per-CVE Correctness (Sorted by CVE Mean Score)</text>',
        '<text x="540" y="50" text-anchor="middle" font-family="Arial" font-size="12" fill="#555">Each line shows CVE-level mean correctness per model across 23 attributes</text>',
    ]

    for tick in [1, 2, 3, 4, 5]:
        yy = y(tick)
        parts.append(f'<line x1="{margin_l}" y1="{yy:.2f}" x2="{width - margin_r}" y2="{yy:.2f}" stroke="#e6e6e6" stroke-width="1"/>')
        parts.append(f'<text x="{margin_l - 10}" y="{yy + 4:.2f}" text-anchor="end" font-family="Arial" font-size="12" fill="#444">{tick}</text>')

    for frac, label in [(0.0, "0%"), (0.25, "25%"), (0.5, "50%"), (0.75, "75%"), (1.0, "100%")]:
        xx = margin_l + frac * plot_w
        parts.append(f'<line x1="{xx:.2f}" y1="{margin_t}" x2="{xx:.2f}" y2="{height - margin_b}" stroke="#f1f1f1" stroke-width="1"/>')
        parts.append(f'<text x="{xx:.2f}" y="{height - margin_b + 24}" text-anchor="middle" font-family="Arial" font-size="12" fill="#444">{label}</text>')

    parts.append(f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{height - margin_b}" stroke="#222" stroke-width="1.5"/>')
    parts.append(f'<line x1="{margin_l}" y1="{height - margin_b}" x2="{width - margin_r}" y2="{height - margin_b}" stroke="#222" stroke-width="1.5"/>')

    for model, values in model_to_scores.items():
        values = sorted(values)
        points = " ".join(f"{x(i):.2f},{y(v):.2f}" for i, v in enumerate(values))
        color = COLORS[model]
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.2" points="{points}"/>')

    legend_x = width - margin_r - 200
    legend_y = margin_t + 10
    for i, model in enumerate(model_to_scores.keys()):
        yy = legend_y + i * 22
        color = COLORS[model]
        parts.append(f'<line x1="{legend_x}" y1="{yy}" x2="{legend_x + 22}" y2="{yy}" stroke="{color}" stroke-width="3"/>')
        parts.append(f'<text x="{legend_x + 30}" y="{yy + 4}" font-family="Arial" font-size="13" fill="#222">{esc(model)}</text>')

    parts.append(f'<text x="{margin_l - 50}" y="{margin_t - 8}" font-family="Arial" font-size="12" fill="#333">Score</text>')
    parts.append(f'<text x="{margin_l + plot_w / 2}" y="{height - 20}" text-anchor="middle" font-family="Arial" font-size="12" fill="#333">Sorted CVE position (percentile)</text>')
    parts.append("</svg>")
    (OUT_DIR / "correctness_cve_sorted.svg").write_text("\n".join(parts), encoding="utf-8")


def main():
    model_to_scores = {}
    for model, name in MODEL_FILES.items():
        path = SCORES_DIR / name
        model_to_scores[model] = read_cve_means(path)

    model_mean = []
    for model, scores in model_to_scores.items():
        model_mean.append((model, sum(scores) / len(scores)))
    model_mean.sort(key=lambda x: x[1], reverse=True)

    write_model_mean_bar_chart(model_mean)
    write_sorted_cve_lines(model_to_scores)
    print("Wrote:", OUT_DIR / "correctness_model_mean.svg")
    print("Wrote:", OUT_DIR / "correctness_cve_sorted.svg")


if __name__ == "__main__":
    main()
