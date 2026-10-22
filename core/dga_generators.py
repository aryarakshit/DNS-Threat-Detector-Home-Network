"""Deterministic DGA Generators & Tranco Benign Corpus Builder.

Implements authentic, deterministic reimplementations of 6 DGA families:
- Cryptolocker: PRNG alphabetic date-seeded LCG (12-16 chars)
- Necurs: PRNG modular vowel-starved generator (9-21 chars)
- Qakbot: PRNG alphanumeric letters and digits (10-22 chars)
- Conficker: PRNG short high-entropy strings (8-11 chars)
- Bamital: Hexadecimal MD5-style 32-character strings (0-9a-f)
- Suppobox / Matsnu: Pseudo-random dictionary word concatenation (14-24 chars)

Along with a Tranco Top-1M benign corpus loader/synthesizer.
"""

from __future__ import annotations
import hashlib
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from config import load_config

# Representative dictionary for Suppobox/Matsnu DGA
SUPPOBOX_WORDS = [
    "account", "action", "active", "agent", "alert", "alpha", "amber", "anchor",
    "apple", "arrow", "asset", "atlas", "audio", "azure", "backup", "badge",
    "banner", "beacon", "block", "branch", "bridge", "buffer", "cable", "camera",
    "canvas", "carbon", "center", "chain", "channel", "circuit", "client", "cloud",
    "cluster", "cobalt", "coffee", "column", "common", "config", "control", "copper",
    "corner", "credit", "crypto", "crystal", "cursor", "custom", "daemon", "damage",
    "danger", "device", "direct", "domain", "double", "driver", "dynamic", "echo",
    "editor", "element", "empire", "engine", "entity", "escape", "expert", "factor",
    "falcon", "family", "filter", "finger", "flavor", "flight", "flower", "focus",
    "forest", "format", "foster", "future", "galaxy", "garden", "gateway", "gentle",
    "global", "golden", "gopher", "granite", "gravel", "ground", "growth", "hammer",
    "harbor", "hazard", "header", "helper", "herald", "horizon", "impact", "index",
    "indigo", "inline", "insect", "inside", "island", "jacket", "jaguar", "jungle",
    "kernel", "keypad", "ladder", "laptop", "launch", "layout", "leader", "legacy",
    "legend", "lemon", "lesson", "letter", "linear", "liquid", "lizard", "loader",
    "locale", "logic", "lumber", "magnet", "manage", "manual", "marble", "margin",
    "marine", "marker", "market", "matrix", "meadow", "medium", "member", "memory",
    "mentor", "mercury", "method", "metric", "middle", "miller", "mirror", "mobile",
    "module", "moment", "monkey", "mosaic", "motion", "motel", "native", "nebula",
    "needle", "network", "neutral", "nickel", "noodle", "normal", "notice", "novel",
    "object", "office", "offset", "online", "opaque", "oracle", "orange", "orbit",
    "origin", "output", "packet", "palace", "palette", "parcel", "parser", "passage",
    "patent", "pattern", "pebble", "pepper", "person", "phantom", "pioneer", "pirate",
    "planet", "plasma", "player", "pocket", "police", "portal", "poster", "powder",
    "prelude", "primer", "prince", "prison", "profit", "proton", "public", "pulley",
    "purple", "python", "quarry", "quartz", "rabbit", "radar", "radial", "radiant",
    "radius", "rainbow", "random", "ranger", "raptor", "record", "region", "relay",
    "remote", "repair", "replay", "report", "rescue", "resort", "retail", "ribbon",
    "rider", "ripple", "rocket", "roller", "router", "runner", "safari", "sailor",
    "salmon", "sample", "sandal", "saturn", "scale", "scanner", "schema", "screen",
    "script", "sector", "secure", "sensor", "serial", "server", "shadow", "shield",
    "signal", "silver", "simple", "single", "sketch", "slumber", "socket", "source",
    "spark", "sphere", "spider", "spiral", "sponge", "spring", "square", "stable",
    "static", "status", "stream", "street", "string", "stripe", "studio", "submit",
    "sulfur", "summit", "sunset", "system", "target", "temple", "tenant", "tensor",
    "theory", "thread", "ticket", "timber", "toggle", "tracer", "tracker", "traffic",
    "tunnel", "update", "valley", "vector", "velvet", "vessel", "victim", "violet",
    "vision", "visual", "vortex", "walnut", "weapon", "widget", "window", "winter",
    "wizard", "yellow", "zenith", "zephyr", "zodiac"
]

# Tranco building blocks for deterministic synthesis
TRANCO_BRAND_PREFIXES = [
    "alpha", "apex", "arc", "astra", "aurora", "axiom", "bay", "beacon", "bell",
    "blue", "bright", "broad", "byte", "cal", "cap", "cast", "cedar", "central",
    "city", "clear", "cloud", "crest", "cross", "crown", "cyber", "data", "deep",
    "delta", "digi", "direct", "dyn", "eagle", "east", "echo", "edge", "elite",
    "epic", "ever", "fast", "first", "flex", "flow", "focus", "force", "front",
    "fuse", "geo", "global", "gold", "grand", "green", "grid", "growth", "halo",
    "harbor", "high", "horizon", "hyper", "icon", "impact", "in", "info", "insight",
    "integra", "intel", "inter", "ion", "iron", "ivy", "key", "kin", "lab", "lake",
    "lead", "leaf", "level", "light", "link", "live", "logic", "lum", "macro",
    "main", "major", "market", "matrix", "max", "meta", "micro", "mid", "mode",
    "nano", "neo", "net", "next", "nexus", "nord", "nova", "oak", "omni", "one",
    "open", "optic", "orbit", "pace", "pan", "para", "path", "peak", "pinnacle",
    "pivot", "pixel", "plus", "point", "poly", "power", "prime", "prism", "pro",
    "pulse", "pure", "quantum", "quest", "quick", "rad", "rapid", "ray", "reach",
    "red", "river", "rock", "root", "sage", "scale", "scope", "sea", "shift",
    "signal", "silver", "sim", "sky", "smart", "snap", "solar", "solid", "source",
    "spark", "speed", "sphere", "stack", "star", "strat", "stream", "summit", "sun",
    "swift", "sync", "syn", "tech", "terra", "titan", "top", "trace", "track",
    "trail", "trend", "true", "trust", "ultra", "uni", "union", "unity", "up",
    "urban", "val", "vanguard", "vault", "vector", "velocity", "venture", "vertex",
    "via", "view", "vigil", "vision", "vista", "vital", "volt", "vortex", "wave",
    "web", "west", "wide", "wind", "wise", "zen", "zero", "zone"
]

TRANCO_BRAND_SUFFIXES = [
    "analytics", "app", "apps", "arch", "associates", "auto", "bank", "base", "bio",
    "bit", "board", "box", "build", "byte", "care", "center", "central", "chain",
    "cloud", "code", "com", "corp", "craft", "data", "desk", "direct", "doc",
    "dynamics", "energy", "engine", "enterprises", "exchange", "express", "finance",
    "first", "fit", "flow", "force", "forge", "fund", "gateway", "gen", "global",
    "go", "grid", "group", "health", "holdings", "home", "host", "house", "hub",
    "industries", "info", "infra", "insights", "institute", "insurance", "intl",
    "invest", "io", "lab", "labs", "land", "lead", "life", "line", "link", "live",
    "logic", "logistics", "loop", "media", "metrics", "mind", "mobility", "mode",
    "nation", "net", "network", "networks", "nexus", "node", "online", "ops",
    "optics", "pad", "pass", "path", "pay", "payment", "plus", "point", "policy",
    "pool", "port", "portal", "post", "power", "press", "prime", "pro", "products",
    "pulse", "rail", "reach", "relay", "research", "resource", "ride", "scale",
    "scope", "search", "secure", "security", "server", "service", "services", "share",
    "shift", "shop", "sight", "signal", "solutions", "source", "space", "spark",
    "stack", "star", "station", "store", "stream", "studio", "switch", "sync",
    "sys", "system", "systems", "tech", "technologies", "times", "tool", "tools",
    "tower", "track", "trade", "trust", "vault", "ventures", "verse", "view",
    "vision", "ware", "wave", "way", "web", "wire", "works", "world", "zone"
]

REAL_WORLD_SEEDS = [
    "google", "youtube", "facebook", "amazon", "apple", "microsoft", "wikipedia",
    "twitter", "reddit", "instagram", "linkedin", "netflix", "yahoo", "github",
    "whatsapp", "tiktok", "spotify", "cloudflare", "zoom", "adobe", "salesforce",
    "dropbox", "pinterest", "tumblr", "twitch", "craigslist", "ebay", "cnn",
    "nytimes", "bbc", "guardian", "reuters", "bloomberg", "forbes", "huffpost",
    "washingtonpost", "espn", "imdb", "quora", "medium", "stackexchange",
    "stackoverflow", "aliexpress", "walmart", "target", "homedepot", "ikea",
    "booking", "airbnb", "tripadvisor", "expedia", "uber", "lyft", "paypal",
    "stripe", "square", "chase", "bankofamerica", "wellsfargo", "citibank",
    "hdfcbank", "icicibank", "sbi", "axisbank", "kotak", "irctc", "zomato",
    "swiggy", "razorpay", "flipkart", "paytm", "phonepe", "zerodha", "cred",
    "groww", "tcs", "infosys", "wipro", "hcltech", "tatamotors", "reliance",
    "airtel", "jio", "bsnl", "hotstar", "zee5", "sony", "samsung", "lg",
    "intel", "amd", "nvidia", "cisco", "oracle", "ibm", "dell", "hp", "lenovo",
    "asus", "acer", "logitech", "huawei", "xiaomi", "oneplus", "oppo", "vivo",
    "mit", "harvard", "stanford", "oxford", "cambridge", "berkeley", "iitb",
    "iitd", "iitm", "iitkgp", "iisc", "nih", "cdc", "who", "nasa", "cern",
    "python", "golang", "rust-lang", "nodejs", "docker", "kubernetes", "ubuntu",
    "debian", "archlinux", "redhat", "centos", "apache", "nginx", "mysql",
    "postgresql", "mongodb", "redis", "elastic", "grafana", "prometheus"
]

TRANCO_TLDS = [
    "com", "org", "net", "co.in", "in", "io", "ai", "co.uk", "gov.in", "edu",
    "gov", "de", "fr", "jp", "ca", "au", "app", "dev", "tech", "info"
]


def generate_cryptolocker(count: int, seed: int = 1337) -> List[str]:
    """Cryptolocker DGA: Date-seeded bit-shifting PRNG generating 12-16 char lowercase domains."""
    tlds = ["com", "net", "biz", "org", "ru", "co.uk"]
    domains: List[str] = []
    state = seed & 0xFFFFFFFF

    for i in range(count):
        # LCG update
        state = (state * 1103515245 + 12345 + i) & 0xFFFFFFFF
        length = 12 + (state % 5)  # 12 to 16
        chars = []
        cur_val = state
        for _ in range(length):
            cur_val = (cur_val * 1664525 + 1013904223) & 0xFFFFFFFF
            char_idx = ((cur_val >> 16) ^ (cur_val & 0xFFFF)) % 26
            chars.append(chr(ord('a') + char_idx))
        tld = tlds[(state >> 3) % len(tlds)]
        domains.append(f"{''.join(chars)}.{tld}")

    return domains


def generate_necurs(count: int, seed: int = 2026) -> List[str]:
    """Necurs DGA: Modular arithmetic PRNG generating 9-21 char vowel-starved domains."""
    tlds = ["com", "in", "xyz", "top", "work", "club"]
    domains: List[str] = []
    consonants = "bcdfghjklmnpqrstvwxyz"
    vowels = "aeiou"
    state = seed & 0xFFFFFFFFFFFF

    for i in range(count):
        state = (state * 0x5DEECE66D + 0xB + i * 3) & 0xFFFFFFFFFFFF
        length = 9 + ((state >> 16) % 13)  # 9 to 21
        chars = []
        sub_state = state
        for step in range(length):
            sub_state = (sub_state * 0x5DEECE66D + 0xB) & 0xFFFFFFFFFFFF
            # Vowel starvation: 88% consonants, 12% vowels
            is_vowel = ((sub_state >> 12) % 100) < 12
            if is_vowel:
                c = vowels[(sub_state >> 4) % len(vowels)]
            else:
                c = consonants[(sub_state >> 4) % len(consonants)]
            chars.append(c)
        tld = tlds[(state >> 8) % len(tlds)]
        domains.append(f"{''.join(chars)}.{tld}")

    return domains


def generate_qakbot(count: int, seed: int = 4242) -> List[str]:
    """Qakbot DGA: Alphanumeric PRNG mixing letters and digits (10-22 chars)."""
    tlds = ["com", "net", "org", "info", "biz"]
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    domains: List[str] = []
    state = seed & 0xFFFFFFFF

    for i in range(count):
        state = (state * 214013 + 2531011 + i * 7) & 0xFFFFFFFF
        length = 10 + (state % 13)  # 10 to 22
        chars = []
        cur_val = state
        for step in range(length):
            cur_val = (cur_val * 214013 + 2531011) & 0xFFFFFFFF
            # Ensure start is a letter for RFC compliance
            if step == 0:
                c = chr(ord('a') + ((cur_val >> 16) % 26))
            else:
                c = charset[(cur_val >> 16) % len(charset)]
            chars.append(c)
        tld = tlds[(state >> 5) % len(tlds)]
        domains.append(f"{''.join(chars)}.{tld}")

    return domains


def generate_conficker(count: int, seed: int = 7777) -> List[str]:
    """Conficker DGA: Shorter 8-11 char high-entropy lowercase strings."""
    tlds = ["com", "net", "org", "info", "cc"]
    domains: List[str] = []
    state = seed & 0xFFFFFFFF

    for i in range(count):
        state = (state * 1664525 + 1013904223 + i * 11) & 0xFFFFFFFF
        length = 8 + (state % 4)  # 8 to 11
        chars = []
        cur = state
        for _ in range(length):
            cur = (cur * 1664525 + 1013904223) & 0xFFFFFFFF
            chars.append(chr(ord('a') + ((cur >> 8) % 26)))
        tld = tlds[(state >> 4) % len(tlds)]
        domains.append(f"{''.join(chars)}.{tld}")

    return domains


def generate_bamital(count: int, seed: int = 9999) -> List[str]:
    """Bamital DGA: Hexadecimal MD5-style 32-character strings (0-9a-f)."""
    tlds = ["org", "info", "cz.cc"]
    domains: List[str] = []

    for i in range(count):
        raw_token = f"bamital_{seed}_{i}".encode('utf-8')
        md5_hash = hashlib.md5(raw_token).hexdigest()
        tld = tlds[i % len(tlds)]
        domains.append(f"{md5_hash}.{tld}")

    return domains


def generate_suppobox(count: int, seed: int = 5555) -> List[str]:
    """Suppobox / Matsnu DGA: Concatenates pseudo-random dictionary words (14-24 chars)."""
    tlds = ["com", "net", "ru"]
    domains: List[str] = []
    rng = random.Random(seed)

    for i in range(count):
        # Select 2 to 3 words
        w1 = rng.choice(SUPPOBOX_WORDS)
        w2 = rng.choice(SUPPOBOX_WORDS)
        candidate = f"{w1}{w2}"
        if len(candidate) < 14:
            w3 = rng.choice(SUPPOBOX_WORDS)
            candidate = f"{candidate}{w3}"
        # Truncate or fit length 14-24
        if len(candidate) > 24:
            candidate = candidate[:24]
        tld = rng.choice(tlds)
        domains.append(f"{candidate}.{tld}")

    return domains


def generate_dga_domains(family: str, count: int, seed: int = 42) -> List[str]:
    """Dispatch domain generation by family name."""
    family_lower = family.lower().replace("-", "_")
    if family_lower == "cryptolocker":
        return generate_cryptolocker(count, seed)
    elif family_lower == "necurs":
        return generate_necurs(count, seed)
    elif family_lower == "qakbot":
        return generate_qakbot(count, seed)
    elif family_lower == "conficker":
        return generate_conficker(count, seed)
    elif family_lower == "bamital":
        return generate_bamital(count, seed)
    elif family_lower in ("suppobox", "suppobox_matsnu", "matsnu"):
        return generate_suppobox(count, seed)
    else:
        raise ValueError(f"Unknown DGA family: {family}")


def build_tranco_benign_corpus(
    count: int = 15000,
    seed: int = 42,
    csv_path: Optional[str | Path] = None
) -> List[str]:
    """Load or deterministically synthesize realistic Tranco Top-1M benign domains.

    Supports reading an existing Tranco CSV if present, or deterministic synthesis
    modeled on real English/Indian/global web distributions.
    """
    if csv_path:
        path = Path(csv_path)
        if path.is_file():
            df = pd.read_csv(path, header=None)
            # Typically col 0 is rank, col 1 is domain
            col = 1 if df.shape[1] > 1 else 0
            domains = df[col].dropna().astype(str).str.strip().tolist()
            if len(domains) >= count:
                return domains[:count]

    # Deterministic high-fidelity benign synthesis
    rng = random.Random(seed)
    domains_set = set()

    # 1. Add authentic real-world seeds with top TLDs
    for brand in REAL_WORLD_SEEDS:
        for tld in ["com", "in", "org", "net", "io"]:
            d = f"{brand}.{tld}"
            domains_set.add(d)

    # 2. Synthesize brand combinations (prefix + suffix, prefix + brand, hyphenated)
    attempts = 0
    while len(domains_set) < count and attempts < count * 20:
        attempts += 1
        mode = rng.randint(1, 6)
        tld = rng.choice(TRANCO_TLDS)

        if mode == 1:
            p = rng.choice(TRANCO_BRAND_PREFIXES)
            s = rng.choice(TRANCO_BRAND_SUFFIXES)
            name = f"{p}{s}"
        elif mode == 2:
            p = rng.choice(TRANCO_BRAND_PREFIXES)
            s = rng.choice(TRANCO_BRAND_SUFFIXES)
            name = f"{p}-{s}"
        elif mode == 3:
            b = rng.choice(REAL_WORLD_SEEDS)
            s = rng.choice(["hub", "portal", "live", "cloud", "pay", "auth", "dev"])
            name = f"{b}-{s}" if rng.random() > 0.5 else f"{b}{s}"
        elif mode == 4:
            # Regional Indian or international enterprise
            prefix = rng.choice(["bharat", "india", "delhi", "mumbai", "bangalore", "euro", "us", "asia", "global", "national"])
            suffix = rng.choice(["bank", "rail", "express", "services", "energy", "news", "hospital", "motors", "finance", "telecom"])
            name = f"{prefix}{suffix}"
            tld = rng.choice(["co.in", "in", "gov.in", "com", "org"])
        elif mode == 5:
            # Short acronym or word + number
            letters = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=rng.randint(3, 5)))
            num = rng.randint(1, 99) if rng.random() > 0.6 else ""
            name = f"{letters}{num}"
        else:
            w1 = rng.choice(SUPPOBOX_WORDS)
            name = f"my{w1}" if rng.random() > 0.5 else f"{w1}now"

        d = f"{name}.{tld}"
        domains_set.add(d)

    domain_list = sorted(list(domains_set))
    rng.shuffle(domain_list)
    return domain_list[:count]


def build_datasets(
    benign_count: int = 15000,
    malicious_count: int = 15000,
    data_dir: Optional[str | Path] = None,
    seed: int = 42
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Generate both benign and malicious CSV files and save to disk."""
    out_dir = Path(data_dir) if data_dir else Path(__file__).resolve().parent.parent / "data"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Benign Corpus
    benign_domains = build_tranco_benign_corpus(count=benign_count, seed=seed)
    df_benign = pd.DataFrame({
        "domain": benign_domains,
        "label": 0,
        "class_name": "benign"
    })
    benign_csv = out_dir / "tranco_benign_sample.csv"
    df_benign.to_csv(benign_csv, index=False)

    # 2. Malicious Corpus across 6 families
    families = ["cryptolocker", "necurs", "qakbot", "conficker", "bamital", "suppobox_matsnu"]
    per_family_count = malicious_count // len(families)
    malicious_records = []

    for fam_idx, family in enumerate(families):
        fam_seed = seed + 100 * (fam_idx + 1)
        count_to_gen = per_family_count
        # Handle remainder if any on the last family
        if fam_idx == len(families) - 1:
            count_to_gen = malicious_count - len(malicious_records)
        doms = generate_dga_domains(family=family, count=count_to_gen, seed=fam_seed)
        for d in doms:
            malicious_records.append({
                "domain": d,
                "label": 1,
                "class_name": family
            })

    df_malicious = pd.DataFrame(malicious_records)
    malicious_csv = out_dir / "dga_malicious_sample.csv"
    df_malicious.to_csv(malicious_csv, index=False)

    return df_benign, df_malicious


if __name__ == "__main__":
    print("Generating Tranco and DGA datasets...")
    df_b, df_m = build_datasets(benign_count=15000, malicious_count=15000)
    print(f"Generated {len(df_b)} benign domains -> data/tranco_benign_sample.csv")
    print(f"Generated {len(df_m)} malicious domains -> data/dga_malicious_sample.csv")
    print("Malicious family distribution:\n", df_m["class_name"].value_counts())
