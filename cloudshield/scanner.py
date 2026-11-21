"""Read-only AWS security configuration checks for CloudShield."""

from typing import Any


def finding(resource, check, status, severity, message, recommendation):
    return {
        "resource": str(resource),
        "check": check,
        "status": status,
        "severity": severity,
        "message": message,
        "recommendation": recommendation,
    }


def scan_s3_buckets(s3_client: Any) -> list[dict[str, str]]:
    """Check S3 public-access-block settings and default encryption."""
    findings = []
    for bucket in s3_client.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            config = s3_client.get_public_access_block(Bucket=name)
            settings = config.get("PublicAccessBlockConfiguration", {})
            enabled = all(settings.get(key, False) for key in (
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets",
            ))
            findings.append(finding(
                name, "s3_public_access_block",
                "PASS" if enabled else "FAIL",
                "INFO" if enabled else "HIGH",
                "All four public access block settings are enabled."
                if enabled else "One or more public access block settings are disabled.",
                "No action required." if enabled else
                "Review exposure requirements and enable all four public access block settings where appropriate.",
            ))
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
            missing = code == "NoSuchPublicAccessBlockConfiguration"
            findings.append(finding(
                name, "s3_public_access_block",
                "FAIL" if missing else "ERROR", "HIGH" if missing else "UNKNOWN",
                "No bucket-level public access block configuration was found."
                if missing else f"Could not inspect public access settings ({code or 'unexpected error'}).",
                "Review public exposure and configure the four block settings."
                if missing else "Check read-only IAM permissions and retry.",
            ))

        try:
            result = s3_client.get_bucket_encryption(Bucket=name)
            rules = result.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            configured = bool(rules)
            findings.append(finding(
                name, "s3_default_encryption",
                "PASS" if configured else "FAIL",
                "INFO" if configured else "MEDIUM",
                "Default server-side encryption is configured."
                if configured else "No default server-side encryption rule was returned.",
                "No action required." if configured else
                "Review data requirements and configure default server-side encryption.",
            ))
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
            missing = code == "ServerSideEncryptionConfigurationNotFoundError"
            findings.append(finding(
                name, "s3_default_encryption",
                "FAIL" if missing else "ERROR", "MEDIUM" if missing else "UNKNOWN",
                "Default server-side encryption is not configured."
                if missing else f"Could not inspect encryption settings ({code or 'unexpected error'}).",
                "Review data requirements and configure default encryption."
                if missing else "Check read-only IAM permissions and retry.",
            ))
    return findings


def scan_ec2(ec2_client: Any) -> list[dict[str, str]]:
    """Check public administrative ingress and EBS volume encryption."""
    findings = []
    groups = ec2_client.describe_security_groups().get("SecurityGroups", [])
    for group in groups:
        group_id = group.get("GroupId", "unknown-security-group")
        for permission in group.get("IpPermissions", []):
            protocol = permission.get("IpProtocol")
            start = permission.get("FromPort", -1)
            end = permission.get("ToPort", -1)
            sensitive = protocol == "-1" or (
                isinstance(start, int) and isinstance(end, int)
                and ((start <= 22 <= end) or (start <= 3389 <= end))
            )
            if not sensitive:
                continue
            public = any(
                item.get("CidrIp") == "0.0.0.0/0"
                for item in permission.get("IpRanges", [])
            ) or any(
                item.get("CidrIpv6") == "::/0"
                for item in permission.get("Ipv6Ranges", [])
            )
            if public:
                findings.append(finding(
                    group_id, "ec2_public_admin_ingress", "FAIL", "HIGH",
                    "A security group allows public ingress to SSH/RDP or all protocols.",
                    "Restrict administrative access to trusted IP ranges or a managed access path.",
                ))
    for volume in ec2_client.describe_volumes().get("Volumes", []):
        volume_id = volume.get("VolumeId", "unknown-volume")
        encrypted = volume.get("Encrypted", False)
        findings.append(finding(
            volume_id, "ebs_encryption",
            "PASS" if encrypted else "FAIL",
            "INFO" if encrypted else "MEDIUM",
            "EBS volume encryption is enabled." if encrypted else "EBS volume encryption is disabled.",
            "No action required." if encrypted else
            "Plan an encrypted replacement volume and migration using AWS guidance.",
        ))
    return findings


def scan_cloudtrail(cloudtrail_client: Any) -> list[dict[str, str]]:
    """Check whether returned CloudTrail trails are actively logging."""
    trails = cloudtrail_client.describe_trails(
        includeShadowTrails=False
    ).get("trailList", [])
    if not trails:
        return [finding(
            "AWS account", "cloudtrail_logging", "FAIL", "HIGH",
            "No CloudTrail trail was returned for this region/account.",
            "Review audit requirements and configure multi-region CloudTrail logging.",
        )]
    findings = []
    for trail in trails:
        name = trail.get("TrailARN") or trail.get("Name", "unknown-trail")
        try:
            logging = cloudtrail_client.get_trail_status(Name=name).get("IsLogging", False)
            findings.append(finding(
                name, "cloudtrail_logging",
                "PASS" if logging else "FAIL",
                "INFO" if logging else "HIGH",
                "CloudTrail is currently logging." if logging else "CloudTrail is not currently logging.",
                "No action required." if logging else "Review audit requirements and enable trail logging.",
            ))
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
            findings.append(finding(
                name, "cloudtrail_logging", "ERROR", "UNKNOWN",
                f"Could not inspect trail status ({code or 'unexpected error'}).",
                "Check read-only CloudTrail permissions and retry.",
            ))
    return findings


def scan_aws_account(session: Any) -> list[dict[str, str]]:
    """Run supported read-only checks in the configured AWS region."""
    region = session.region_name
    if not region:
        raise ValueError("No AWS region configured. Set --region or configure a default region.")
    findings = []
    findings.extend(scan_s3_buckets(session.client("s3", region_name=region)))
    findings.extend(scan_ec2(session.client("ec2", region_name=region)))
    findings.extend(scan_cloudtrail(session.client("cloudtrail", region_name=region)))
    return findings
