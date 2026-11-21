from cloudshield.scanner import scan_s3_buckets


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


def test_secure_bucket_passes_both_checks():
    client = FakeS3Client(
        public_access={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        encryption=[
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
        ],
    )

    findings = scan_s3_buckets(client)

    assert len(findings) == 2
    assert all(finding["status"] == "PASS" for finding in findings)


def test_disabled_public_access_block_is_high_severity():
    client = FakeS3Client(
        public_access={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        encryption=[
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
        ],
    )

    findings = scan_s3_buckets(client)
    public_access = next(
        finding
        for finding in findings
        if finding["check"] == "s3_public_access_block"
    )

    assert public_access["status"] == "FAIL"
    assert public_access["severity"] == "HIGH"


def test_missing_default_encryption_is_medium_severity():
    client = FakeS3Client(
        public_access={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        encryption=[],
    )

    findings = scan_s3_buckets(client)
    encryption = next(
        finding
        for finding in findings
        if finding["check"] == "s3_default_encryption"
    )

    assert encryption["status"] == "FAIL"
    assert encryption["severity"] == "MEDIUM"
