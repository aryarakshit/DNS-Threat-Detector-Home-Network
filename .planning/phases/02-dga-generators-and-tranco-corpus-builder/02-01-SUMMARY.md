# Summary: 02-01 DGA Generators & Tranco Corpus Builder

## Deliverables
- `core/dga_generators.py`:
  - Authentic deterministic implementations for all 6 DGA families:
    1. Cryptolocker (date-seeded PRNG, 12-16 chars, alphabetic)
    2. Necurs (modular arithmetic PRNG, 9-21 chars, vowel-starved)
    3. Qakbot (alphanumeric PRNG, 10-22 chars, mixed letters and digits)
    4. Conficker (PRNG short high-entropy strings, 8-11 chars)
    5. Bamital (MD5 hexadecimal 32-character hashes, 0-9a-f)
    6. Suppobox / Matsnu (concatenation of dictionary words, 14-24 chars)
  - Tranco benign corpus loader & synthesizer generating 15,000 realistic domains with natural web lexical distributions.
- Generated datasets:
  - `data/tranco_benign_sample.csv` (15,000 benign domains, label=0)
  - `data/dga_malicious_sample.csv` (15,000 malicious domains, label=1, 2,500 across each of the 6 families)

## Verification Evidence
- Verified row counts with Pandas: exactly 15,000 benign and 15,000 malicious domains.
- Verified exact family balance: 2,500 samples per DGA family.
- Checked sample domains across all 6 families confirming strict adherence to length, character set, and TLD constraints.
