# CloudShield architecture

CloudShield is a read-only Python CLI tool. It uses the AWS SDK for Python (Boto3) to inspect configuration and returns normalized findings.

```text
User
 |
 | cloudshield --demo
 | cloudshield --profile audit-readonly --region ap-south-1
 v
Command-line interface (cloudshield/cli.py)
 |
 +---- Demo mode ----> samples/sample_findings.json
 |
 +---- Live mode ----> Boto3 Session (read-only AWS identity)
                         |
                         +--> Amazon S3 checks
                         |      - Public access block
                         |      - Default encryption
                         +--> Amazon EC2 checks
                         |      - Public SSH/RDP ingress
                         |      - EBS volume encryption
                         +--> AWS CloudTrail check
                                - Trail logging status
 |
 v
Normalized findings
 |
 +--> JSON report
 +--> Standalone HTML report
```

## Security design

- The scanner makes read-only API calls and does not change AWS resources.
- Credentials are obtained from the normal AWS SDK credential chain or a named AWS CLI profile. No credentials are stored in this repository.
- Demo mode uses bundled synthetic findings and does not connect to AWS.
- Checks are regional where AWS services are regional. Run the scanner in each region required by your audit.
- A missing permission is reported as an error where the individual check can continue; it is not silently treated as a passing check.

## Current scope

This is an educational portfolio project, not a complete CSPM product or compliance certification tool. It does not evaluate every AWS service, bucket policy nuance, organization-wide account, or every route to public exposure.
