"""
build_injection_index.py — Build the FAISS prompt-injection index
=================================================================
Run this once after downloading the adversarial text datasets.
See datasets/README.md for download instructions.

Usage:
    python agents/build_injection_index.py --input datasets/all_adversarial.json
    python agents/build_injection_index.py --input datasets/prompt_injections.json --build-corpus
"""

from __future__ import annotations

import argparse
import json
import logging
import random
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("build_injection_index")

_BASE      = Path(__file__).resolve().parents[1]  # → Varaksha/
MODELS_DIR = _BASE / "data" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Synthetic legitimate UPI memos for the KL-divergence baseline corpus
LEGIT_TEMPLATES = [
    "Rent for {month}", "EMI {month}", "Groceries", "Fuel", "Electricity bill",
    "Water bill", "Gas bill", "OTT subscription", "Thanks", "Recharge",
    "Food order", "Medicine", "School fees", "Gym fee", "Salary",
    "Insurance premium", "Mobile bill", "Broadband bill", "Maintenance",
    "Parking fee", "Auto fare", "Cab fare", "Coffee", "Snacks",
    "Book purchase", "Stationery", "Donation", "Wedding gift", "Birthday",
    "Trip expense", "Hotel", "Flight", "Railway ticket", "Bus ticket",
]
MONTHS = ["January","February","March","April","May","June",
          "July","August","September","October","November","December"]


def build_legit_corpus(n: int = 2000) -> list[str]:
    rng = random.Random(42)
    corpus = []
    for _ in range(n):
        tmpl = rng.choice(LEGIT_TEMPLATES)
        text = tmpl.format(month=rng.choice(MONTHS)) if "{month}" in tmpl else tmpl
        # Add minor variation
        if rng.random() < 0.3:
            text = text.lower()
        corpus.append(text)
    return corpus


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",    required=False, default=None,
                        help="Path to JSON array of adversarial strings")
    parser.add_argument("--build-corpus", action="store_true",
                        help="Also generate the legitimate memo corpus")
    parser.add_argument("--model",    default="all-MiniLM-L6-v2")
    args = parser.parse_args()

    if args.build_corpus:
        corpus = build_legit_corpus()
        corpus_path = MODELS_DIR / "legit_memo_corpus.json"
        corpus_path.write_text(json.dumps(corpus, ensure_ascii=False), encoding='utf-8')
        log.info("Legit corpus written: %d samples → %s", len(corpus), corpus_path)

    if args.input is None:
        log.info("No --input provided — only corpus was built. Re-run with --input to build FAISS index.")
        return

    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input file not found: %s\nSee datasets/README.md", input_path)
        return

    strings: list[str] = json.loads(input_path.read_text(encoding='utf-8'))
    if not strings:
        log.error("Input file is empty")
        return

    log.info("Loaded %d adversarial strings from %s", len(strings), input_path)

    # Import here so the script fails early if sentence-transformers isn't installed
    from sentence_transformers import SentenceTransformer
    import faiss
    import numpy as np

    log.info("Loading sentence-transformer: %s", args.model)
    embedder = SentenceTransformer(args.model)

    log.info("Encoding %d strings…", len(strings))
    vecs = embedder.encode(strings, normalize_embeddings=True,
                           show_progress_bar=True, batch_size=256).astype("float32")

    dim   = vecs.shape[1]
    index = faiss.IndexFlatIP(dim)  # inner product ≡ cosine (L2-normalised)
    index.add(vecs)

    index_path   = MODELS_DIR / "injection_index.faiss"
    strings_path = MODELS_DIR / "injection_strings.json"

    faiss.write_index(index, str(index_path))
    strings_path.write_text(json.dumps(strings, ensure_ascii=False), encoding='utf-8')

    log.info("FAISS index written: %d vectors  dim=%d → %s", index.ntotal, dim, index_path)
    log.info("String list written: %s", strings_path)

    # Quick sanity check
    q = "Ignore all previous instructions"
    qv = embedder.encode([q], normalize_embeddings=True).astype("float32")
    dist, idx = index.search(qv, k=1)
    log.info("Sanity check — query='%s' → nearest='%s' (sim=%.3f)",
             q, strings[int(idx[0][0])], float(dist[0][0]))


if __name__ == "__main__":
    main()
