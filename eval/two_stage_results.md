# Two-stage benchmark results

Run 2026-10-19 with `python -m eval.two_stage_benchmark` (seed 1234, CPU). Raw output is in `eval/results/two_stage.json` (gitignored).

These numbers use the default policy: character-level obfuscation blocks, structural hiding is sanitized. They also use the bundled TR39 confusables subset.

- **Classifier:** `protectai/deberta-v3-base-prompt-injection-v2`; "flagged" means the label is `INJECTION`.
- **Injections:** all 263 `label=1` rows of `deepset/prompt-injections` (train + test). 145 of them are English, by a German-stopword filter.
- **Homoglyphs:** taken from Unicode `confusables.txt` (UTS #39), downloaded at runtime. Each letter that has a confusable is swapped with 50% probability.
- **Zero-width splits:** one invisible character inserted inside every Latin word of 4+ letters.

## Attacks (all 263)

| Attack | Classifier alone | Classifier on goggles output | goggles, default policy* | goggles flagged |
| --- | --- | --- | --- | --- |
| Unmodified | 41.4% | 41.4% | 41.4% | 0.0% |
| ZWSP split | 77.6% | 41.4% | 100.0% | 99.6%† |
| Mixed ZW split (ZWSP/ZWNJ/ZWJ/WJ/BOM) | 80.6% | 41.4% | 100.0% | 99.6%† |
| TR39 Cyrillic/Greek homoglyphs | 98.1% | 51.3% | 100.0% | 99.6%† |
| TR39 any-script homoglyphs | 84.0% | 48.7% | 100.0% | 100.0% |
| Homoglyphs + ZWSP | 99.2% | 52.1% | 100.0% | 100.0% |
| CSS-hidden payload in an HTML page | 30.4% | n/a | 100.0% (payload stripped) | 100.0% |

\* Default policy: an attack counts as caught if goggles blocks it, strips the payload, or the classifier flags goggles' sanitized output.

† The one unflagged sample was left unchanged by the attack, so nothing was hidden. For the zero-width splits it's letter-spaced text with no 4+ letter words to split. For the homoglyph variant it's a Khmer prompt with no Latin letters to swap. goggles flagged every sample that was actually obfuscated.

The English-only subset (n=145) follows the same pattern. Unmodified: 42.1% alone. ZWSP split: 69.0% alone, 100% with goggles.

How much of the homoglyph swap goggles undid, after bundling the TR39 subset (was 48.5% / 7.9% with the old hand-picked map):

| Variant | Swapped characters mapped back |
| --- | --- |
| Cyrillic/Greek | 89.5% |
| Any script | 90.7% |

The remaining ~10% are deliberate exemptions: single letters and short Greek+Latin symbols are left alone so scientific text isn't blocked. Those leftover lookalikes are why the classifier still scores ~50% on sanitized homoglyph text.

## Benign text (815 samples)

| Bucket | n | goggles flag rate | Text unchanged |
| --- | --- | --- | --- |
| deepset benign prompts | 399 | 0.0% | 99.5% (stray ZWSPs at word boundaries removed) |
| Non-Latin text (ru, bg, el, ar, ur, hi, th, ja, zh) | 108 | 0.0% | 99.1% (one stray ZWSP removed) |
| Latin-script text (de, fr, es, it, pt, nl, pl, tr, vi) | 108 | 0.0% | 100% |
| Emoji ZWJ / modifier / tag / keycap sequences | 100 | 0.0% | 100% |
| Everyday HTML (comments, grid/flex CSS, code, alt text) | 100 | 0.0% | n/a |

0 of 815 bounds the true false-flag rate at about 0.4% (95%, rule of three). The classifier's false-positive rate on the benign prompts is 1.0%, both on the raw text and on goggles' output.

## What this means

1. **Obfuscation raises this classifier's score instead of blinding it.** Recall went from 41% on clean text to 78–99% on obfuscated text, and sanitizing returns it to baseline. goggles doesn't make the classifier better.
2. **goggles' detection is the signal.** It flagged every obfuscated sample and blocked it under the default policy, with zero false flags on 815 benign samples.
3. **The classifier misses most hidden payloads.** It flagged 30% of CSS-hidden instructions; goggles stripped all of them.
4. **Scope.** This benchmark tests the attack families goggles is built for. It says nothing about visible prompt injection, which goggles doesn't detect.
5. **Low baseline.** ProtectAI flags 41% of deepset's injections in the clear (42% English-only). Many deepset "injections" are mild role-play or opinion prompts.
