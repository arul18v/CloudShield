"""Command-line interface for CloudShield."""

import argparse
import json
from pathlib import Path

import boto3

from cloudshield.report import write_reports
from cloudshield.scanner import scan_aws_account


def main():
    parser = argparse.ArgumentParser(
        description="Read-only AWS security configuration auditor."
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use bundled sample findings; no AWS connection.",
    )
    parser.add_argument("--profile", help="AWS CLI profile name for a live read-only scan.")
    parser.add_argument("--region", default=None, help="AWS region, e.g. ap-south-1.")
    parser.add_argument("--output", default="reports", help="Directory for JSON and HTML reports.")
    args = parser.parse_args()

    if args.demo:
        sample_path = Path(__file__).resolve().parent.parent / "samples" / "sample_findings.json"
        findings = json.loads(sample_path.read_text(encoding="utf-8"))
        source = "Demo data (no AWS connection)"
    else:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        findings = scan_aws_account(session)
        source = f"AWS account scan ({session.region_name})"

    json_path, html_path = write_reports(findings, args.output, source)
    passed = sum(item["status"] == "PASS" for item in findings)
    failed = sum(item["status"] == "FAIL" for item in findings)
    errors = sum(item["status"] == "ERROR" for item in findings)

    print(f"CloudShield scan complete: {source}")
    print(
        f"Checks: {len(findings)} | Passed: {passed} | "
        f"Failed: {failed} | Errors: {errors}"
    )
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")


if __name__ == "__main__":
    main()
