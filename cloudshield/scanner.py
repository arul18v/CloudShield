"""Read-only AWS S3 security checks for CloudShield.

This module reports basic bucket configuration findings. It does not modify
AWS resources. Pass in a boto3 S3 client so the checks can be tested locally.
"""

from typing import Any


def _finding(
    resource: str,
    check: str,
    status: str,
    severity: str,
    message: str,
    recommendation: str,
) -> dict[str, str]:
    """Build a consistent finding dictionary."""
    return {
        "resource": resource,
        "check": check,
        "status": status,
        "severity": severity,
        "message": message,
        "recommendation": recommendation,
    }


def scan_s3_buckets(s3_client: Any) -> list[dict[str, str]]:
    """Check S3 bucket public-access blocks and default encryption.

    The supplied client should have read-only permissions for:
    s3:ListAllMyBuckets, s3:GetPublicAccessBlock, and
    s3:GetEncryptionConfiguration.
    """
    findings: list[dict[str, str]] = []

    response = s3_client.list_buckets()

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        # Check whether all four S3 public-access-block settings are enabled.
        try:
            config = s3_client.get_public_access_block(Bucket=bucket_name)
            settings = config.get("PublicAccessBlockConfiguration", {})
            all_enabled = all(
                settings.get(key, False)
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )

            if all_enabled:
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_public_access_block",
                        "PASS",
                        "INFO",
                        "All S3 public access block settings are enabled.",
                        "No action required.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_public_access_block",
                        "FAIL",
                        "HIGH",
                        "One or more S3 public access block settings are disabled.",
                        "Review the bucket's public access requirements and enable "
                        "all four public access block settings where appropriate.",
                    )
                )
        except Exception as error:
            error_code = getattr(error, "response", {}).get(
                "Error", {}
            ).get("Code", "")

            if error_code == "NoSuchPublicAccessBlockConfiguration":
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_public_access_block",
                        "FAIL",
                        "HIGH",
                        "No bucket-level public access block configuration was found.",
                        "Review the bucket's public access requirements and configure "
                        "all four public access block settings where appropriate.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_public_access_block",
                        "ERROR",
                        "UNKNOWN",
                        f"Could not check public access settings ({error_code or 'unexpected error'}).",
                        "Verify that the scanning identity has the required read-only permission.",
                    )
                )

        # Check whether default server-side encryption is configured.
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get(
                "ServerSideEncryptionConfiguration", {}
            ).get("Rules", [])

            if rules:
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_default_encryption",
                        "PASS",
                        "INFO",
                        "Default server-side encryption is configured.",
                        "No action required.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_default_encryption",
                        "FAIL",
                        "MEDIUM",
                        "No default server-side encryption rule was found.",
                        "Review the bucket's data requirements and configure default "
                        "server-side encryption.",
                    )
                )
        except Exception as error:
            error_code = getattr(error, "response", {}).get(
                "Error", {}
            ).get("Code", "")

            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_default_encryption",
                        "FAIL",
                        "MEDIUM",
                        "Default server-side encryption is not configured.",
                        "Review the bucket's data requirements and configure default "
                        "server-side encryption.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        bucket_name,
                        "s3_default_encryption",
                        "ERROR",
                        "UNKNOWN",
                        f"Could not check encryption settings ({error_code or 'unexpected error'}).",
                        "Verify that the scanning identity has the required read-only permission.",
                    )
                )

    return findings
