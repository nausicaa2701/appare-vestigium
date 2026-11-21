"""Command-line entry point: ``raven <subcommand>``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from raven import __version__
from raven.config import REPO_ROOT, ConfigError, load_config
from raven.manifest import ManifestError, verify_manifest
from raven.runlog import start_run

DEFAULT_MANIFEST = REPO_ROOT / "artifacts" / "data" / "manifest.csv"


def _cmd_noop(args: argparse.Namespace) -> int:
    config = load_config(args.config, seed=args.seed)
    with start_run(config, "noop", argv=["raven", *args.argv]) as run:
        run.logger.info("noop: no work performed; run directory %s", run.path)
    print(run.path)
    return 0


def _cmd_check_config(args: argparse.Namespace) -> int:
    load_config(args.config, seed=args.seed)
    print(f"{args.config}: ok")
    return 0


def _phase(command: str, work: Callable) -> Callable[[argparse.Namespace], int]:
    pass

    def handler(args: argparse.Namespace) -> int:
        config = load_config(args.config, seed=args.seed)
        with start_run(config, command, argv=["raven", *args.argv]) as run:
            work(run, args)
        print(run.path)
        return 0

    return handler


def _p2_inventory(run, args):
    from raven import p2

    p2.run_inventory(run)


def _p2_select(run, args):
    from raven import p2

    p2.run_select(run, args.inventory_run)


def _p2_recover(run, args):
    from raven import p2

    p2.run_recover(run, args.inventory_run, args.select_run, args.source)


def _p2_audit(run, args):
    from raven import p2

    p2.run_audit(run, args.inventory_run, args.select_run, args.recover_run)


def _p3_acquire(run, args):
    from raven import p3

    p3.run_acquire(run, args.inventory_run)


def _p3_overlap(run, args):
    from raven import p3

    p3.run_overlap(run, args.inventory_run, args.select_run, args.identities_run)


def _p3_check(run, args):
    from raven import p3

    p3.check_split(run, args.inventory_run, args.select_run, args.overlap_run, args.php)


def _p4_secbench(run, args):
    from raven import p4

    p4.run_secbench_repro(run, args.inventory_run, args.select_run, args.overlap_run, args.recover_run)


def _p4_align(run, args):
    from raven import p4

    p4.run_jsvul_align(run, args.inventory_run, args.select_run, args.overlap_run, args.recover_run)


def _p4_php(run, args):
    from raven import p4

    p4.run_php_twins(run, args.inventory_run, args.select_run, args.overlap_run)


def _p4_summary(run, args):
    from raven import p4

    p4.run_summary(run, args.overlap_run, args.check_run, args.secbench_run, args.align_run, args.php_run)


def _p5_review_cases(run, args):
    from raven import p5
    p5.run_review_cases(run, args.p4_summary_run)


def _p5_extract(run, args):
    from raven import p5
    p5.run_extract_units(run, args.p4_summary_run)


def _p5_contexts(run, args):
    from raven import p5
    p5.run_contexts(run, args.extract_run, args.review_run)


def _p5_necessity(run, args):
    from raven import p5
    p5.run_necessity(run, args.extract_run, args.build_run, args.review_file, args.reviewer, args.date)


def _p5_judge(run, args):
    from raven import judge
    judge.run_judge(run, args.build_run, args.review_set, args.calibration_run, judge_config=args.judge_config)


def _p5_agreement(run, args):
    from raven import judge
    judge.run_agreement(run, args.necessity_run, args.judge_run)


def _p5_adjudication(run, args):
    from raven import judge
    judge.run_adjudication(run, args.agreement_run, args.worksheet)


def _p5c_correction(run, args):
    from raven import p5c
    p5c.run_correction(run, args.necessity_run, args.adjudication_run, args.worksheet)


def _p6_pack(run, args):
    from raven import p6
    p6.run_pack(run, args.extract_run, args.build_run, args.p5c_run)


def _p6_leakage(run, args):
    from raven import leakage
    leakage.run_leakage(run, args.extract_run, args.build_run, args.pack_run)


def _p6_packets(run, args):
    from raven import p6review
    p6review.run_packets(run, args.extract_run, args.build_run, args.pack_run)


def _p6_review_check(run, args):
    from raven import p6review
    p6review.run_review_check(run, args.packets_run, args.review)


def _p7_train(run, args):
    from raven import detector
    detector.run_train(run, args.pack_run, args.fold, args.variant, args.extract_run, args.build_run, args.max_steps,
                       resume=args.resume, stop_after=args.stop_after)


def _p7_score(run, args):
    from raven import detector
    detector.run_score(run, args.pack_run, args.train_run)


def _p7_selector(run, args):
    from raven import p7s4
    p7s4.run_selector(run, args.train_run, args.pack_run, args.resume)


def _p7_gate(run, args):
    from raven import p7a
    p7a.run_gate(run, args.train_runs)


def _p7_manifest(run, args):
    from raven import p7
    p7.run_manifest(run, args.extract_run, args.build_run, args.p5c_run, args.pack_run)


def _p7_evidence(run, args):
    from raven import p7
    p7.run_evidence(run, args.manifest_run, args.extract_run, args.build_run)


def _cmd_verify_manifest(args: argparse.Namespace) -> int:
    results = verify_manifest(args.manifest, args.data_root)
    for result in results:
        print(f"{'OK  ' if result.ok else 'FAIL'} {result.id}: {result.reason}")
    failed = sum(not r.ok for r in results)
    print(f"{len(results)} rows, {failed} failed")
    if args.require_rows and not results:
        print("manifest has no rows but --require-rows was given", file=sys.stderr)
        return 1
    return 1 if failed else 0


from raven.detector import ScoringRoleError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="raven", description="Appare Vestigium pilot tooling")
    parser.add_argument("--version", action="version", version=f"raven {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<subcommand>")

    noop = sub.add_parser("noop", help="validate config and create a run directory only")
    noop.add_argument("--config", required=True, type=Path)
    noop.add_argument("--seed", type=int, help="override the config seed")
    noop.set_defaults(func=_cmd_noop)

    check = sub.add_parser("check-config", help="validate a config without creating a run")
    check.add_argument("--config", required=True, type=Path)
    check.add_argument("--seed", type=int, help="override the config seed")
    check.set_defaults(func=_cmd_check_config)

    verify = sub.add_parser("verify-manifest", help="check SHA-256 of every manifest row")
    verify.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    verify.add_argument("--data-root", type=Path, help="defaults to $RAVEN_DATA_ROOT")
    verify.add_argument("--require-rows", action="store_true", help="fail on an empty manifest")
    verify.set_defaults(func=_cmd_verify_manifest)

    def phase(name: str, help_text: str, work) -> argparse.ArgumentParser:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--config", required=True, type=Path)
        cmd.add_argument("--seed", type=int, help="override the config seed")
        cmd.set_defaults(func=_phase(name, work))
        return cmd

    phase("inventory", "P2: full metadata inventory of every source", _p2_inventory)
    select = phase("select-subsets", "P2: hash-ordered capped subsets", _p2_select)
    select.add_argument("--inventory-run", required=True, type=Path)
    recover = phase("recover", "P2: recover snapshots for the subsets", _p2_recover)
    recover.add_argument("--inventory-run", required=True, type=Path)
    recover.add_argument("--select-run", required=True, type=Path)
    recover.add_argument("--source", action="append", required=True, choices=("jsvul", "secbench", "sard_php"))
    audit = phase("audit-summary", "P2: provenance audit summary and spot check", _p2_audit)
    audit.add_argument("--inventory-run", required=True, type=Path)
    audit.add_argument("--select-run", required=True, type=Path)
    audit.add_argument("--recover-run", action="append", required=True, type=Path)

    acquire = phase("acquire-identities", "P3: npm/GitHub identity data for overlap control", _p3_acquire)
    acquire.add_argument("--inventory-run", required=True, type=Path)
    overlap = phase("overlap", "P3: equivalence groups, purge, splits and roles", _p3_overlap)
    overlap.add_argument("--inventory-run", required=True, type=Path)
    overlap.add_argument("--select-run", required=True, type=Path)
    overlap.add_argument("--identities-run", required=True, type=Path)
    check = phase("check-split", "P3: verify split/purge/role invariants", _p3_check)
    check.add_argument("--inventory-run", required=True, type=Path)
    check.add_argument("--select-run", required=True, type=Path)
    check.add_argument("--overlap-run", required=True, type=Path)
    check.add_argument("--php", action="store_true", help="also check the PHP compositional split")

    sb = phase("secbench-repro", "P4: reproduce SecBench vulnerable/fixed pairs in isolated containers", _p4_secbench)
    for flag in ("--inventory-run", "--select-run", "--overlap-run", "--recover-run"):
        sb.add_argument(flag, required=True, type=Path)
    al = phase("jsvul-align", "P4: align JsVul bodies to the original source at the revision", _p4_align)
    for flag in ("--inventory-run", "--select-run", "--overlap-run", "--recover-run"):
        al.add_argument(flag, required=True, type=Path)
    ph = phase("php-twins", "P4: structural PHP twin validation and offline php -l", _p4_php)
    for flag in ("--inventory-run", "--select-run", "--overlap-run"):
        ph.add_argument(flag, required=True, type=Path)
    sm = phase("p4-summary", "P4: pair statuses, C0-C3, gate 5c check", _p4_summary)
    for flag in ("--overlap-run", "--check-run", "--secbench-run", "--align-run", "--php-run"):
        sm.add_argument(flag, required=True, type=Path)

    rc = phase("review-cases", "P5: necessity-review case list (pilot_dev, before review)", _p5_review_cases)
    rc.add_argument("--p4-summary-run", required=True, type=Path)
    ex = phase("extract-units", "P5: tree-sitter units, parse status and target mapping", _p5_extract)
    ex.add_argument("--p4-summary-run", required=True, type=Path)
    bc = phase("build-contexts", "P5: graph, L0-L3, length profile, conflicts, PHP sanitizers", _p5_contexts)
    bc.add_argument("--extract-run", required=True, type=Path)
    bc.add_argument("--review-run", required=True, type=Path)
    nr = phase("necessity-review", "P5: validate the human necessity review; evidence selectability", _p5_necessity)
    nr.add_argument("--extract-run", required=True, type=Path)
    nr.add_argument("--build-run", required=True, type=Path)
    nr.add_argument("--review-file", required=True, type=Path)
    nr.add_argument("--reviewer", required=True, help="fills empty reviewer cells (the file's own values win)")
    nr.add_argument("--date", required=True, help="fills empty date cells, ISO date")
    jd = phase("judge", "P5: auxiliary LLM judge on one review set (billable; gated by judge.yaml)", _p5_judge)
    jd.add_argument("--build-run", required=True, type=Path)
    jd.add_argument("--review-set", required=True, choices=("calibration", "validation"))
    jd.add_argument("--calibration-run", type=Path, help="required for validation: the run that froze the prompt")
    jd.add_argument("--judge-config", type=Path, help="judge config (default: p5.review.judge in --config)")
    ag = phase("judge-agreement", "P5: human-LLM agreement and adjudication template", _p5_agreement)
    ag.add_argument("--necessity-run", required=True, type=Path)
    ag.add_argument("--judge-run", action="append", required=True, type=Path)
    ad = phase("judge-adjudication", "P5: validate the human adjudication worksheet; final labels", _p5_adjudication)
    ad.add_argument("--agreement-run", required=True, type=Path)
    ad.add_argument("--worksheet", required=True, type=Path)
    pc = phase("p5c-correction", "P5C: apply a dated span/scope correction; regenerate selectability",
               _p5c_correction)
    pc.add_argument("--necessity-run", required=True, type=Path)
    pc.add_argument("--adjudication-run", required=True, type=Path)
    pc.add_argument("--worksheet", required=True, type=Path)
    pk = phase("pack-cells", "P6: exact budget packing, provenance manifest and coverage (controls only)", _p6_pack)
    pk.add_argument("--extract-run", required=True, type=Path)
    pk.add_argument("--build-run", required=True, type=Path)
    pk.add_argument("--p5c-run", required=True, type=Path)
    lk = phase("leakage-probes", "P6: path/comment/bag-of-words leakage probes; label-conflict rerun", _p6_leakage)
    lk.add_argument("--extract-run", required=True, type=Path)
    lk.add_argument("--build-run", required=True, type=Path)
    lk.add_argument("--pack-run", required=True, type=Path)
    sp = phase("source-map-packets", "P6: complete source-map review packets and R1 review template", _p6_packets)
    sp.add_argument("--extract-run", required=True, type=Path)
    sp.add_argument("--build-run", required=True, type=Path)
    sp.add_argument("--pack-run", required=True, type=Path)
    sc = phase("source-map-review-check", "P6: validate R1's filled source-map review copy", _p6_review_check)
    sc.add_argument("--packets-run", required=True, type=Path)
    sc.add_argument("--review", required=True, type=Path)
    dt = phase("detector-train", "P7A: train the detector (pilot_dev only; role guard before loading input)",
               _p7_train)
    dt.add_argument("--pack-run", required=True, type=Path)
    dt.add_argument("--resume", type=Path, default=None)
    dt.add_argument("--stop-after", type=int, default=None, help="checkpoint and pause after this optimizer step")
    dt.add_argument("--fold", default="0", choices=["0", "1", "2", "final"])
    dt.add_argument("--variant", default=None, choices=["no_dropout", "context_dropout"])
    dt.add_argument("--extract-run", type=Path, default=None)
    dt.add_argument("--build-run", type=Path, default=None)
    dt.add_argument("--max-steps", type=int, default=None, help="smoke runs only; excluded from the gate")
    ds = phase("detector-score", "P7A: score with a frozen detector (pilot_dev only; role guard first)", _p7_score)
    ds.add_argument("--pack-run", required=True, type=Path)
    ds.add_argument("--train-run", type=Path, default=None)
    dg = phase("detector-gate", "P7A: pooled outer-assessment gate over the cross-fit train runs", _p7_gate)
    dg.add_argument("--train-runs", nargs="+", required=True, type=Path)
    ps = phase("p7-selector", "P7 S4: minimal selector learning run against a frozen detector", _p7_selector)
    ps.add_argument("--train-run", required=True, type=Path)
    ps.add_argument("--pack-run", type=Path, help="required for the legacy selector path")
    ps.add_argument("--resume", type=Path, default=None)
    pm = phase("p7-manifest", "P7 S0: cohort, split and evidence manifests (before any outcome)", _p7_manifest)
    pm.add_argument("--extract-run", required=True, type=Path)
    pm.add_argument("--build-run", required=True, type=Path)
    pm.add_argument("--p5c-run", required=True, type=Path)
    pm.add_argument("--pack-run", required=True, type=Path)
    pe = phase("p7-evidence", "P7 S3: real-code evidence and graph-sensitivity probe (no detector)", _p7_evidence)
    pe.add_argument("--manifest-run", required=True, type=Path)
    pe.add_argument("--extract-run", required=True, type=Path)
    pe.add_argument("--build-run", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(argv)
    args.argv = argv
    try:
        return args.func(args)
    except (ConfigError, ManifestError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ScoringRoleError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
