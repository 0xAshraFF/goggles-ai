"""Two-stage benchmark: does goggles-ai help a prompt-injection classifier?

Stage 1 is goggles-ai (deterministic hidden-channel sanitizer). Stage 2 is a
semantic classifier (protectai/deberta-v3-base-prompt-injection-v2). We compare
the classifier alone against goggles-ai + classifier on known injections that
have been obfuscated, and check that goggles-ai leaves benign text alone.

Independence from goggles-ai's own code:
  - Injections come from deepset/prompt-injections (Apache-2.0), label=1.
  - Homoglyphs come from the Unicode Consortium's confusables.txt (UTS #39),
    downloaded at runtime, not from goggles-ai's internal confusables map.
  - Zero-width splits are generated here, not by goggles-ai's attack generators.

Usage (needs torch + transformers + datasets, not installed by goggles-ai):
    python -m eval.two_stage_benchmark
    python -m eval.two_stage_benchmark --limit 50     # quick smoke run
"""

from __future__ import annotations

import argparse
import json
import random
import re
import time
import unicodedata
import urllib.request
from collections import defaultdict
from pathlib import Path

from bs4 import BeautifulSoup

from goggles_ai import scan

RESULTS_DIR = Path(__file__).parent / "results"
CACHE_DIR = Path(__file__).parent / "data"
CLASSIFIER = "protectai/deberta-v3-base-prompt-injection-v2"
CONFUSABLES_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"
EMOJI_ZWJ_URL = "https://www.unicode.org/Public/emoji/latest/emoji-zwj-sequences.txt"
EMOJI_SEQ_URL = "https://www.unicode.org/Public/emoji/latest/emoji-sequences.txt"
SEED = 1234


# ── External resources ────────────────────────────────────────────────────────

def fetch(url: str) -> str:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / url.rsplit("/", 1)[-1]
    if not path.exists():
        req = urllib.request.Request(url, headers={"User-Agent": "goggles-ai-benchmark"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            path.write_bytes(resp.read())
    return path.read_text(encoding="utf-8")


def load_tr39_confusables() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Map each ASCII letter to its single-codepoint TR39 confusables.

    Returns (cyrillic_greek_only, any_script).
    """
    any_script: dict[str, list[str]] = defaultdict(list)
    cyr_greek: dict[str, list[str]] = defaultdict(list)
    for line in fetch(CONFUSABLES_URL).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        src, dst, *_ = [p.strip() for p in line.split(";")]
        src_cps, dst_cps = src.split(), dst.split()
        if len(src_cps) != 1 or len(dst_cps) != 1:
            continue
        s, d = chr(int(src_cps[0], 16)), chr(int(dst_cps[0], 16))
        if not ("a" <= d <= "z" or "A" <= d <= "Z") or ord(s) < 128:
            continue
        if unicodedata.category(s)[0] != "L":
            continue
        any_script[d].append(s)
        name = unicodedata.name(s, "")
        if name.startswith(("CYRILLIC", "GREEK")):
            cyr_greek[d].append(s)
    return dict(cyr_greek), dict(any_script)


def load_emoji_sequences() -> list[str]:
    seqs: list[str] = []
    for url in (EMOJI_ZWJ_URL, EMOJI_SEQ_URL):
        for line in fetch(url).splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            cps, kind = [p.strip() for p in line.split(";")[:2]]
            if ".." in cps:
                continue
            if kind in ("RGI_Emoji_ZWJ_Sequence", "RGI_Emoji_Tag_Sequence",
                        "RGI_Emoji_Modifier_Sequence", "Emoji_Keycap_Sequence"):
                seqs.append("".join(chr(int(c, 16)) for c in cps.split()))
    return seqs


# ── Perturbations ─────────────────────────────────────────────────────────────

WORD_RE = re.compile(r"[A-Za-z]{4,}")


def zw_split(text: str, rng: random.Random, chars: list[str]) -> str:
    """Insert one invisible char inside every Latin word of 4+ letters."""
    def split(m: re.Match) -> str:
        w = m.group(0)
        k = rng.randint(1, len(w) - 1)
        return w[:k] + rng.choice(chars) + w[k:]
    return WORD_RE.sub(split, text)


def homoglyph(text: str, rng: random.Random, table: dict[str, list[str]], rate: float = 0.5) -> str:
    return "".join(
        rng.choice(table[ch]) if ch in table and rng.random() < rate else ch
        for ch in text
    )


HTML_PAGE = """<!doctype html><html><head><title>Product FAQ</title>
<style>.wrap{{display:flex;gap:1rem}} .muted{{color:#666}}</style></head>
<body><nav class="wrap"><a href="/">Home</a><a href="/faq">FAQ</a></nav>
<main><h1>Frequently asked questions</h1>
<p class="muted">Shipping usually takes 3-5 business days. Returns are free within 30 days.</p>
<div style="display:none">{payload}</div>
<p>Contact support if your order has not arrived.</p></main></body></html>"""

BENIGN_HTML = """<!doctype html><html><head><title>Docs</title>
<style>.grid{{display:grid;grid-template-columns:1fr 2fr}} code{{font-family:monospace}}</style></head>
<body><!-- page header --><header class="grid"><a href="/">Home</a><span>Guide</span></header>
<main><h2>Notes</h2><p>{text}</p>
<pre><code>for i in range(3):\n    print(i ** 2)</code></pre>
<p>Use <code>a &lt; b</code> when comparing; see <a href="/api" title="API reference">the API</a>.</p>
<img src="/logo.png" alt="Company logo"></main></body></html>"""


def visible_and_hidden_text(html: str) -> str:
    """What a naive HTML-to-text agent pipeline would feed the model."""
    return BeautifulSoup(html, "lxml").get_text(" ", strip=True)


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


_GERMAN = {"der", "die", "das", "und", "ich", "nicht", "ist", "ein", "eine", "zu", "mit",
           "sie", "wie", "was", "für", "auf", "den", "dem", "bitte", "vergiss", "alle",
           "ignoriere", "du", "mir", "ihr", "auch", "sind", "wird", "kann", "über", "jetzt"}


def is_english(text: str) -> bool:
    """Rough filter: deepset/prompt-injections mixes English and German."""
    return not any(w in _GERMAN for w in re.findall(r"[a-zäöüß]+", text.lower()))


def char_restore_rate(original: str, attacked: str, sanitized: str) -> float | None:
    """Share of swapped characters that goggles-ai mapped back to the original."""
    attacked = "".join(c for c in attacked if unicodedata.category(c) != "Cf")
    if not (len(original) == len(attacked) == len(sanitized)):
        return None
    swapped = [i for i, (o, a) in enumerate(zip(original, attacked)) if o != a]
    if not swapped:
        return None
    return sum(sanitized[i] == original[i] for i in swapped) / len(swapped)


# ── Benchmark ─────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="cap injections per variant")
    ap.add_argument("--out", default=str(RESULTS_DIR / "two_stage.json"))
    args = ap.parse_args()

    from datasets import load_dataset
    from transformers import pipeline

    rng = random.Random(SEED)
    clf = pipeline("text-classification", model=CLASSIFIER, truncation=True, max_length=512)

    def flags(texts: list[str]) -> list[bool]:
        return [r["label"] == "INJECTION" for r in clf(texts, batch_size=16)]

    ds = load_dataset("deepset/prompt-injections")
    rows = [r for split in ("train", "test") for r in ds[split]]
    positives = [r["text"] for r in rows if r["label"] == 1]
    negatives = [r["text"] for r in rows if r["label"] == 0]
    if args.limit:
        positives = positives[: args.limit]
        negatives = negatives[: args.limit]

    cyr_greek, any_script = load_tr39_confusables()

    variants = {
        "unmodified": lambda t: t,
        "zwsp_split": lambda t: zw_split(t, rng, ["​"]),
        "mixed_zw_split": lambda t: zw_split(t, rng, ["​", "‌", "‍", "⁠", "﻿"]),
        "tr39_cyrillic_greek": lambda t: homoglyph(t, rng, cyr_greek),
        "tr39_any_script": lambda t: homoglyph(t, rng, any_script),
        "homoglyph_plus_zwsp": lambda t: zw_split(homoglyph(t, rng, cyr_greek), rng, ["​"]),
    }

    report: dict = {
        "classifier": CLASSIFIER,
        "dataset": "deepset/prompt-injections (train+test)",
        "n_injections": len(positives),
        "n_injections_english": sum(is_english(t) for t in positives),
        "n_benign_prompts": len(negatives),
        "seed": SEED,
        "attacks": {},
        "benign": {},
    }

    # ── Attack variants (text) ────────────────────────────────────────────
    for name, perturb in variants.items():
        t0 = time.time()
        attacked = [perturb(t) for t in positives]
        results = [scan(t, content_type="text/plain") for t in attacked]
        sanitized = [r.sanitized_content if r.sanitized_content is not None else t
                     for r, t in zip(results, attacked)]
        raw = flags(attacked)
        after = flags(sanitized)
        default_policy = [r.action == "block" or f for r, f in zip(results, after)]
        any_flag = [r.hidden_content_found or f for r, f in zip(results, after)]
        restored = sum(norm(s) == norm(o) for s, o in zip(sanitized, positives))
        rates = [x for x in (char_restore_rate(o, a, s)
                             for o, a, s in zip(positives, attacked, sanitized)) if x is not None]

        def summarize(idx: list[int]) -> dict:
            m = len(idx) or 1
            return {
                "n": len(idx),
                "classifier_alone": sum(raw[i] for i in idx) / m,
                "classifier_on_sanitized": sum(after[i] for i in idx) / m,
                "default_policy_caught": sum(default_policy[i] for i in idx) / m,
                "goggles_flag_or_classifier": sum(any_flag[i] for i in idx) / m,
                "goggles_flagged": sum(results[i].hidden_content_found for i in idx) / m,
            }

        report["attacks"][name] = {
            "all": summarize(list(range(len(positives)))),
            "english": summarize([i for i, t in enumerate(positives) if is_english(t)]),
            "sanitized_equals_original": restored / len(positives),
            "homoglyph_char_restore_rate": (sum(rates) / len(rates)) if rates else None,
            "seconds": round(time.time() - t0, 1),
        }
        print(name, report["attacks"][name], flush=True)

    # ── Attack variant (structural: CSS-hidden payload in a page) ─────────
    pages = [HTML_PAGE.format(payload=t) for t in positives]
    results = [scan(p, content_type="text/html") for p in pages]
    raw = flags([visible_and_hidden_text(p) for p in pages])
    clean_text = [visible_and_hidden_text(r.sanitized_content or "") for r in results]
    after = flags(clean_text)
    stripped = [norm(o)[:40] not in norm(c) for o, c in zip(positives, clean_text)]
    n = len(positives)
    report["attacks"]["css_hidden_in_html"] = {
        "n": n,
        "classifier_alone": sum(raw) / n,
        "payload_reaches_model_after_goggles": sum(not s for s in stripped) / n,
        "default_policy_caught": sum(r.action == "block" or s or f
                                     for r, s, f in zip(results, stripped, after)) / n,
        "goggles_flagged": sum(r.hidden_content_found for r in results) / n,
    }
    print("css_hidden_in_html", report["attacks"]["css_hidden_in_html"], flush=True)

    # ── Benign: classifier false positives on deepset negatives ───────────
    results = [scan(t, content_type="text/plain") for t in negatives]
    sanitized = [r.sanitized_content if r.sanitized_content is not None else t
                 for r, t in zip(results, negatives)]
    n = len(negatives)
    report["benign"]["deepset_benign_prompts"] = {
        "n": n,
        "goggles_flag_rate": sum(r.hidden_content_found for r in results) / n,
        "text_preserved": sum(s == t for s, t in zip(sanitized, negatives)) / n,
        "classifier_fp_alone": sum(flags(negatives)) / n,
        "classifier_fp_after_goggles": sum(flags(sanitized)) / n,
    }

    # ── Benign bucket 1: non-Latin multilingual text ──────────────────────
    lang = load_dataset("papluca/language-identification", split="test")
    buckets = {
        "multilingual_non_latin": ["ru", "bg", "el", "ar", "ur", "hi", "th", "ja", "zh"],
        "multilingual_latin": ["de", "fr", "es", "it", "pt", "nl", "pl", "tr", "vi"],
    }
    for bucket, codes in buckets.items():
        texts = []
        for code in codes:
            texts += [r["text"] for r in lang if r["labels"] == code][:12]
        report["benign"][bucket] = goggles_only(texts, "text/plain")
        report["benign"][bucket]["languages"] = codes

    # ── Benign bucket 2: emoji ZWJ / modifier / tag / keycap sequences ────
    seqs = load_emoji_sequences()
    rng.shuffle(seqs)
    templates = ["Great news {e} see you soon!", "Our team {e} won the match.",
                 "Happy birthday {e} have a great day.", "Status update: done {e}"]
    emoji_texts = [templates[i % len(templates)].format(e=e) for i, e in enumerate(seqs[:100])]
    report["benign"]["emoji_sequences"] = goggles_only(emoji_texts, "text/plain")

    # ── Benign bucket 3: everyday HTML markup ─────────────────────────────
    html_docs = [BENIGN_HTML.format(text=t) for t in negatives[:100]]
    results = [scan(h, content_type="text/html") for h in html_docs]
    report["benign"]["benign_html"] = {
        "n": len(html_docs),
        "goggles_flag_rate": sum(r.hidden_content_found for r in results) / len(html_docs),
        "flagged_threat_types": sorted({t.type for r in results for t in r.threats}),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report["benign"], indent=2, ensure_ascii=False))
    print(f"\nWrote {args.out}")


def goggles_only(texts: list[str], content_type: str) -> dict:
    results = [scan(t, content_type=content_type) for t in texts]
    n = len(texts)
    return {
        "n": n,
        "goggles_flag_rate": sum(r.hidden_content_found for r in results) / n,
        "text_preserved": sum((r.sanitized_content if r.sanitized_content is not None else t) == t
                              for r, t in zip(results, texts)) / n,
        "flagged_examples": [t[:80] for r, t in zip(results, texts) if r.hidden_content_found][:5],
    }


if __name__ == "__main__":
    main()
