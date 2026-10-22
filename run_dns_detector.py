#!/usr/bin/env python3
"""Master End-to-End Runner for Home-Network DNS DGA & C2 Threat Detector.

Orchestrates:
1. Dataset generation (Tranco benign + 6 DGA families)
2. Model training & 5-fold cross-validation with anti-leakage isolation
3. 7-day home network DNS log simulation (140,000 queries across 5 devices)
4. Telemetry parsing & multi-dimensional threat hunting
5. Automated SOC investigation dossier generation & portfolio markdown report
"""

from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure project root in sys.path and UTF-8 console output on Windows
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import load_config
from core.dga_generators import build_datasets
from core.log_parsers import DNSLogParser, generate_home_network_logs
from core.model_trainer import DGAModelTrainer, load_detector_bundle, predict_domain
from core.threat_hunter import DNSThreatHunter, generate_soc_investigation_report

console = Console(highlight=False, legacy_windows=False)


def print_banner() -> None:
    """Print master CLI banner."""
    banner = """
 [bold cyan]DNS DGA & C2 Threat Detector on Home Networks[/bold cyan]
 [dim]Hybrid Information-Theoretic & Machine Learning SOC Detection Engine[/dim]
"""
    console.print(Panel(banner.strip(), border_style="cyan", expand=False))


def step_train(force: bool = False) -> None:
    """Train or verify ML model."""
    bundle_path = PROJECT_ROOT / "models" / "dga_detector.joblib"
    if bundle_path.is_file() and not force:
        console.print("[green][OK][/green] Trained model bundle already exists at [bold]models/dga_detector.joblib[/bold]. Use [yellow]--force-train[/yellow] to retrain.")
        return

    console.print("\n[bold yellow]► PHASE 1: Training Scikit-Learn Model Pipeline...[/bold yellow]")
    trainer = DGAModelTrainer()
    results = trainer.train_and_evaluate(save_path=bundle_path)
    console.print(f"[bold green][OK] Training Complete![/bold green] Precision: [bold]{results['overall_metrics']['precision']}%[/bold] | Recall: [bold]{results['overall_metrics']['recall']}%[/bold]")


def step_generate_logs(force: bool = False) -> Path:
    """Generate 7-day home DNS logs if missing."""
    log_path = PROJECT_ROOT / "data" / "home_dns_7days.jsonl"
    if log_path.is_file() and not force:
        console.print("[green][OK][/green] 7-Day home DNS telemetry log already exists at [bold]data/home_dns_7days.jsonl[/bold].")
        return log_path

    console.print("\n[bold yellow]► PHASE 2: Simulating 7-Day Home Network DNS Telemetry (140,000 queries)...[/bold yellow]")
    out = generate_home_network_logs(output_path=log_path, total_queries=140000, days=7)
    console.print(f"[bold green][OK] Generated 140,000 DNS queries across 5 LAN hosts -> {out}[/bold green]")
    return out


def step_hunt_and_report(
    log_path: Optional[str | Path] = None,
    report_path: Optional[str | Path] = None
) -> None:
    """Run threat hunting and generate SOC report."""
    console.print("\n[bold yellow]► PHASE 3: Real-Time Threat Hunting & Behavioral Triage...[/bold yellow]")
    hunter = DNSThreatHunter()
    dossiers = hunter.process_log_stream(log_file=log_path)

    # Render summary table in console
    table = Table(title="SOC Triage Investigation Summary", show_header=True, header_style="bold magenta")
    table.add_column("Domain", style="cyan")
    table.add_column("Host IP", style="dim")
    table.add_column("Queries", justify="right")
    table.add_column("NXDOMAIN %", justify="right")
    table.add_column("P(DGA)", justify="right")
    table.add_column("Severity")
    table.add_column("Triage Verdict")

    for d in dossiers:
        sev = d["severity"]
        sev_colored = f"[bold red]{sev}[/bold red]" if sev == "CRITICAL" else f"[green]{sev}[/green]"
        ip_str = ", ".join(d["source_ips"])
        table.add_row(
            d["domain"],
            ip_str,
            str(d["total_queries"]),
            f"{d['nxdomain_ratio']}%",
            f"{d['prob_dga']:.2f}",
            sev_colored,
            d["verdict"]
        )

    console.print(table)

    console.print("\n[bold yellow]► PHASE 4: Generating SOC Dossier Markdown Report...[/bold yellow]")
    rep = generate_soc_investigation_report(
        flagged_dossiers=dossiers,
        output_path=report_path,
        total_queries=140000,
        monitored_days=7
    )
    console.print(f"[bold green][OK] Full SOC Report successfully generated at -> [bold underline]{rep}[/bold underline][/bold green]")


def main() -> None:
    """Master CLI Entrypoint."""
    parser = argparse.ArgumentParser(
        description="Home-Network DNS DGA & C2 Threat Detector CLI Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--all", action="store_true", help="Execute complete end-to-end pipeline (train, log-gen, hunt, report)")
    parser.add_argument("--train", action="store_true", help="Train Random Forest classifier on Tranco/DGA datasets")
    parser.add_argument("--force-train", action="store_true", help="Force model retraining even if model file exists")
    parser.add_argument("--generate-logs", action="store_true", help="Generate 7-day home network DNS log stream")
    parser.add_argument("--force-logs", action="store_true", help="Force re-generation of DNS log stream")
    parser.add_argument("--hunt", action="store_true", help="Run threat hunting on DNS telemetry log")
    parser.add_argument("--report", action="store_true", help="Generate SOC markdown report")
    parser.add_argument("--log-file", type=str, default=None, help="Custom path to Pi-hole or Zeek log file")
    parser.add_argument("--output-report", type=str, default=None, help="Custom output path for report markdown")

    args = parser.parse_args()
    print_banner()

    # Default to --all if no specific action provided
    if not any([args.all, args.train, args.force_train, args.generate_logs, args.force_logs, args.hunt, args.report]):
        args.all = True

    t0 = time.time()

    if args.all or args.train or args.force_train:
        step_train(force=args.force_train)

    if args.all or args.generate_logs or args.force_logs:
        step_generate_logs(force=args.force_logs)

    if args.all or args.hunt or args.report:
        step_hunt_and_report(log_path=args.log_file, report_path=args.output_report)

    console.print(f"\n[dim]Pipeline execution completed in {time.time() - t0:.2f} seconds.[/dim]\n")


if __name__ == "__main__":
    main()
