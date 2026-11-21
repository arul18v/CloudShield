from cloudshield.report import write_reports
from cloudshield.scanner import scan_cloudtrail, scan_ec2, scan_s3_buckets


class FakeS3Client:
    """Fake S3 client used by tests; it never contacts AWS."""

    def __init__(self, public_access, encryption):
        self.public_access = public_access
        self.encryption = encryption

    def list_buckets(self):
        return {"Buckets": [{"Name": "demo-private-bucket"}]}

    def get_public_access_block(self, Bucket):
        return {"PublicAccessBlockConfiguration": self.public_access}

    def get_bucket_encryption(self, Bucket):
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": self.encryption
            }
        }


def secure_public_access():
    return {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }


def test_secure_bucket_passes_both_checks():
    client = FakeS3Client(
        public_access=secure_public_access(),
        encryption=[
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
        ],
    )
    findings = scan_s3_buckets(client)
    assert len(findings) == 2
    assert all(item["status"] == "PASS" for item in findings)


def test_disabled_public_access_block_is_high_severity():
    settings = secure_public_access()
    settings["BlockPublicAcls"] = False
    client = FakeS3Client(
        public_access=settings,
        encryption=[
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
        ],
    )
    findings = scan_s3_buckets(client)
    public_access = next(
        item for item in findings if item["check"] == "s3_public_access_block"
    )
    assert public_access["status"] == "FAIL"
    assert public_access["severity"] == "HIGH"


def test_missing_default_encryption_is_medium_severity():
    client = FakeS3Client(public_access=secure_public_access(), encryption=[])
    findings = scan_s3_buckets(client)
    encryption = next(
        item for item in findings if item["check"] == "s3_default_encryption"
    )
    assert encryption["status"] == "FAIL"
    assert encryption["severity"] == "MEDIUM"


class FakeEC2Client:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [{
                "GroupId": "sg-demo123",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }],
            }]
        }

    def describe_volumes(self):
        return {
            "Volumes": [
                {"VolumeId": "vol-encrypted", "Encrypted": True},
                {"VolumeId": "vol-unencrypted", "Encrypted": False},
            ]
        }


def test_ec2_detects_public_admin_ingress_and_unencrypted_volume():
    findings = scan_ec2(FakeEC2Client())
    checks = {item["check"]: item for item in findings}
    assert checks["ec2_public_admin_ingress"]["status"] == "FAIL"
    assert checks["ec2_public_admin_ingress"]["severity"] == "HIGH"
    assert checks["ebs_encryption"]["status"] == "FAIL"


class FakeCloudTrailClient:
    def describe_trails(self, includeShadowTrails=False):
        return {"trailList": [{"Name": "demo-trail"}]}

    def get_trail_status(self, Name):
        return {"IsLogging": True}


def test_cloudtrail_logging_passes_when_trail_is_logging():
    findings = scan_cloudtrail(FakeCloudTrailClient())
    assert len(findings) == 1
    assert findings[0]["status"] == "PASS"


def test_cloudtrail_without_trails_returns_high_severity_finding():
    class NoTrails:
        def describe_trails(self, includeShadowTrails=False):
            return {"trailList": []}

    findings = scan_cloudtrail(NoTrails())
    assert findings[0]["status"] == "FAIL"
    assert findings[0]["severity"] == "HIGH"


def test_report_writer_creates_json_and_html(tmp_path):
    findings = [{
        "resource": "demo-bucket",
        "check": "s3_default_encryption",
        "status": "FAIL",
        "severity": "MEDIUM",
        "message": "Encryption is not configured.",
        "recommendation": "Review and configure encryption.",
    }]

    json_path, html_path = write_reports(findings, tmp_path, "Test run")

    assert json_path.exists()
    assert html_path.exists()
    assert "demo-bucket" in json_path.read_text(encoding="utf-8")
    assert "CloudShield" in html_path.read_text(encoding="utf-8")
