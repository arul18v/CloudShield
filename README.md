# CloudShield 🛡️

**A read-only AWS security configuration auditor built with Python and Boto3.**

CloudShield inspects selected AWS resource configurations for common security risks and produces JSON and HTML reports. A bundled demo mode lets anyone explore the project without AWS credentials or cloud charges.

## Features

- **Amazon S3:** checks bucket-level Block Public Access settings and default server-side encryption.
- **Amazon EC2:** flags security groups exposing SSH/RDP or all protocols to public IP ranges; checks EBS volume encryption.
- **AWS CloudTrail:** checks whether returned trails are actively logging.
- **Reports:** creates a machine-readable JSON report and a standalone HTML report.
- **Demo mode:** uses synthetic sample findings and makes no AWS connection.
- **Automated tests:** S3 checks are covered by tests using a fake client; GitHub Actions runs pytest.

## Project structure

```text
CloudShield/
├── .github/workflows/tests.yml
├── cloudshield/
│   ├── __init__.py
│   ├── cli.py
│   ├── report.py
│   └── scanner.py
├── docs/architecture.md
├── samples/sample_findings.json
├── tests/test_s3.py
├── requirements.txt
└── README.md
```

## Run locally

Requires Python 3.10 or newer.

```bash
git clone https://github.com/arul18v/CloudShield.git
cd CloudShield
python -m venv .venv
```

Activate the environment:

- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

### Try demo mode (no AWS account required)

```bash
python -m cloudshield.cli --demo
```

The reports are saved in the `reports/` directory:

- `reports/cloudshield-report.html`
- `reports/cloudshield-report.json`

Open the HTML report in a browser.

### Run tests

```bash
pytest -q
```

## Optional: scan an AWS account

Only scan an account you own or are explicitly authorized to assess. Configure the AWS CLI with a dedicated **read-only** identity and a named profile. Never paste access keys into source code or commit credentials.

Example:

```bash
python -m cloudshield.cli --profile audit-readonly --region ap-south-1
```

The scanner uses these read-only API actions:

- S3: `s3:ListAllMyBuckets`, `s3:GetPublicAccessBlock`, `s3:GetEncryptionConfiguration`
- EC2: `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`
- CloudTrail: `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`

EC2 and CloudTrail checks are regional. Run a scan in each relevant region. Missing permissions may produce `ERROR` findings.

## Example output

Running `python -m cloudshield.cli --demo` with the bundled sample dataset produces a summary similar to:

```text
CloudShield scan complete: Demo data (no AWS connection)
Checks: 5 | Passed: 2 | Failed: 3 | Errors: 0
JSON report: reports/cloudshield-report.json
HTML report: reports/cloudshield-report.html
```

The demo dataset contains synthetic examples of passing and failing checks. These are sample records, not findings from a real AWS account.

## Limitations

- CloudShield checks a deliberately small set of controls; it is not a full CSPM platform or compliance certification tool.
- A security-group finding is a configuration signal, not proof that a resource is reachable.
- S3 public access can also depend on account-level settings, bucket policies, access points, and other controls not fully evaluated here.
- Findings are advisory. Validate recommendations against your environment and security requirements.
- CloudShield does not perform automatic remediation.

## Security

The scanner is designed for defensive configuration auditing and uses read-only AWS API operations. Use least-privilege credentials and never commit secrets.

## License

MIT. See [LICENSE](LICENSE).
