"""
Cloud Security Posture Scanner - S3 Checks
Scans all S3 buckets in an AWS account and flags common misconfigurations:
  - Buckets that allow public access
  - Buckets without default encryption enabled
"""

import boto3
import json
from botocore.exceptions import ClientError

# Create clients to talk to the S3 and IAM services
s3_client = boto3.client("s3")
iam_client = boto3.client("iam")

# This will hold all our findings so we can print a summary at the end
findings = []


def check_public_access(bucket_name):
    """Checks whether a bucket blocks public access. Flags it if not."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]


        # If ALL four settings are True, the bucket is fully locked down
        is_fully_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])

        if not is_fully_blocked:
            findings.append({
                "bucket": bucket_name,
                "risk": "HIGH",
                "issue": "Public access is not fully blocked",
                "explanation": (
                    "This bucket's 'Block Public Access' settings are not fully "
                    "enabled, meaning objects could potentially be exposed to "
                    "the public internet depending on bucket policy/ACLs."
                ),
            })

    except ClientError as error:
        # Some buckets have NO public access block config at all set,
        # which AWS treats as an error rather than returning False values.
        # That absence of any config is itself a risk worth flagging.
        if error.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append({
                "bucket": bucket_name,
                "risk": "HIGH",
                "issue": "No public access block configuration exists",
                "explanation": (
                    "This bucket has no public access block settings configured "
                    "at all, meaning it relies entirely on other controls "
                    "(like bucket policy) to prevent public exposure."
                ),
            })
        else:
            print(f"  [!] Could not check public access for {bucket_name}: {error}")


def check_encryption(bucket_name):
    """Checks whether a bucket has default server-side encryption enabled."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        # If this call succeeds without error, encryption IS configured — no finding needed

    except ClientError as error:
        if error.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append({
                "bucket": bucket_name,
                "risk": "MEDIUM",
                "issue": "Default encryption is not enabled",
                "explanation": (
                    "This bucket does not have default server-side encryption "
                    "configured, meaning uploaded objects are not automatically "
                    "encrypted at rest unless encryption is specified at upload time."
                ),
            })
        else:
            print(f"  [!] Could not check encryption for {bucket_name}: {error}")


def is_policy_overly_permissive(policy_document):
    """
    Checks a single policy document for the classic 'wildcard' risk pattern:
    an Allow statement granting Action: '*' on Resource: '*'.
    This means 'do anything, to anything' - the broadest permission possible.
    """
    statements = policy_document.get("Statement", [])

    # A policy can have one statement (a dict) or many (a list) - normalize to a list
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        # Normalize both to lists so we can check membership consistently
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions and "*" in resources:
            return True

    return False


def check_iam_users():
    """Checks all IAM users' attached and inline policies for wildcard permissions."""
    paginator = iam_client.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            # Check managed policies (ones attached from AWS's policy library or custom-made ones)
            attached = iam_client.list_attached_user_policies(UserName=username)
            for policy in attached["AttachedPolicies"]:
                policy_arn = policy["PolicyArn"]
                policy_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                policy_doc = iam_client.get_policy_version(
                    PolicyArn=policy_arn, VersionId=policy_version
                )["PolicyVersion"]["Document"]

                if is_policy_overly_permissive(policy_doc):
                    findings.append({
                        "bucket": f"IAM user: {username}",
                        "risk": "HIGH",
                        "issue": f"Attached policy '{policy['PolicyName']}' grants full access",
                        "explanation": (
                            "This policy allows Action '*' on Resource '*', meaning the "
                            "user can perform ANY action on ANY AWS resource in the account. "
                            "This violates the principle of least privilege."
                        ),
                    })

            # Check inline policies (ones written directly on this specific user, not reusable)
            inline_names = iam_client.list_user_policies(UserName=username)["PolicyNames"]
            for policy_name in inline_names:
                policy_doc = iam_client.get_user_policy(
                    UserName=username, PolicyName=policy_name
                )["PolicyDocument"]

                if is_policy_overly_permissive(policy_doc):
                    findings.append({
                        "bucket": f"IAM user: {username}",
                        "risk": "HIGH",
                        "issue": f"Inline policy '{policy_name}' grants full access",
                        "explanation": (
                            "This policy allows Action '*' on Resource '*', meaning the "
                            "user can perform ANY action on ANY AWS resource in the account. "
                            "This violates the principle of least privilege."
                        ),
                    })


def scan_all_buckets():
    """Main entry point: lists all buckets and runs every check against each one."""
    print("Starting S3 security scan...\n")

    response = s3_client.list_buckets()
    buckets = response["Buckets"]

    if not buckets:
        print("No buckets found in this account.")
        return

    for bucket in buckets:
        bucket_name = bucket["Name"]
        print(f"Scanning bucket: {bucket_name}")
        check_public_access(bucket_name)
        check_encryption(bucket_name)

    print("\nScanning IAM users...")
    check_iam_users()

    print_report()


def print_report():
    """Prints a clean summary report of all findings."""
    print("\n" + "=" * 60)
    print("SECURITY SCAN REPORT")
    print("=" * 60)

    if not findings:
        print("\nNo issues found. All buckets look good!")
        return

    high_risk_count = sum(1 for f in findings if f["risk"] == "HIGH")
    medium_risk_count = sum(1 for f in findings if f["risk"] == "MEDIUM")

    print(f"\nTotal findings: {len(findings)}  ({high_risk_count} High, {medium_risk_count} Medium)\n")

    for finding in findings:
        print(f"[{finding['risk']} RISK] {finding['bucket']}")
        print(f"  Issue: {finding['issue']}")
        print(f"  Why it matters: {finding['explanation']}\n")


if __name__ == "__main__":
    scan_all_buckets()