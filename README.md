# AWS Cloud Security Posture Scanner

A Python tool that connects to AWS and automatically scans an account for common security misconfigurations, like publicly exposed storage or users with excessive permissions, and generates a report flagging what needs fixing.

## Why I Built This

Cloud misconfigurations (not sophisticated hacking) are one of the most common real-world causes of data breaches. Manually checking every storage bucket and every user's permissions in an AWS account is slow and easy to get wrong, especially as an account grows. This tool automates that check, running the same kind of logic that real cloud security tools (like AWS Security Hub) use, just on a smaller scale.

## Security Checks Performed

This scanner runs three specific, well-defined checks:

### 1. S3 Public Access Check
AWS S3 buckets have a setting called **"Block Public Access"**, made up of four sub-settings:
- `BlockPublicAcls`
- `IgnorePublicAcls`
- `BlockPublicPolicy`
- `RestrictPublicBuckets`

If all four are enabled, the bucket is protected from being made public by accident. This scanner checks every bucket's configuration and flags any bucket where these aren't fully enabled, since that means the bucket **could** be exposing files to anyone on the internet, depending on other settings like bucket policy.

### 2. S3 Default Encryption Check
This checks whether a bucket has **default server-side encryption** enabled, meaning files are automatically encrypted at rest as soon as they're uploaded. If this isn't configured, files could be stored unencrypted unless encryption is manually specified at upload time, an easy thing to forget, and a bigger risk if the bucket is ever accessed by someone it shouldn't be.

### 3. IAM Overly Permissive Policy Check ("Wildcard" Check)
Every AWS user has a policy (a JSON document) defining what they're allowed to do. This scanner looks for the single most dangerous pattern possible: a policy that grants **`Action: "*"`** (any action) combined with **`Resource: "*"`** (any resource).

Example of a flagged policy:
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

This effectively means "allow this user to do **anything**, to **anything**" in the AWS account, the cloud equivalent of a master key. This violates the security principle of **least privilege**, which says users should only have the minimum access needed to do their job. For comparison, a safe, scoped-down policy looks like this instead:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": "arn:aws:s3:::specific-bucket-name/*"
}
```

This only allows reading from one specific bucket, much safer, since even if these credentials were ever leaked, the potential damage is limited.

The scanner checks both **attached policies** (reusable policies assigned to a user) and **inline policies** (custom one-off policies written directly for a specific user) for every IAM user in the account.

## How It Works

The tool uses `boto3`, AWS's official Python SDK, to connect to an AWS account using credentials configured locally (never hardcoded in the script itself, a deliberate security choice). It:

1. Lists all S3 buckets in the account and runs the public access + encryption checks against each one
2. Lists all IAM users and checks their policies for the wildcard pattern
3. Collects every issue found into a findings list
4. Prints a clean summary report, showing each issue's risk level and a plain-English explanation of why it matters

## Setup & Usage

**Requirements:**
- Python 3.x
- An AWS account
- `boto3` installed (`pip install boto3`)
- AWS CLI configured with credentials (`aws configure`)

**IAM Permissions needed:** This tool only needs read access. It was built and tested using an IAM user with `AmazonS3ReadOnlyAccess` and `IAMReadOnlyAccess` attached — deliberately scoped down following least-privilege, since the scanner only needs to read configurations, not modify anything.

**Run it:**
```bash
python project.py
```

## Sample Output

```
Starting S3 security scan...
Scanning bucket: thisenc-private-test-bucket
Scanning bucket: thisenc-public-test-bucket
Scanning IAM users...
============================================================
SECURITY SCAN REPORT
============================================================
Total findings: 2  (2 High, 0 Medium)
[HIGH RISK] thisenc-public-test-bucket
  Issue: Public access is not fully blocked
  Why it matters: This bucket's 'Block Public Access' settings are not fully enabled,
  meaning objects could potentially be exposed to the public internet depending on
  bucket policy/ACLs.
[HIGH RISK] IAM user: test-overprivileged-user
  Issue: Attached policy 'AdministratorAccess' grants full access
  Why it matters: This policy allows Action '*' on Resource '*', meaning the user can
  perform ANY action on ANY AWS resource in the account. This violates the principle
  of least privilege.
```

## What I Learned

While testing, my "private" test bucket was unexpectedly flagged as a public access risk. Rather than assuming the code was wrong, I added a debug print statement to inspect the raw configuration values AWS was returning, which showed the bucket's actual settings didn't match what I'd intended when creating it in the console. I fixed the bucket's configuration directly and re-ran the scan to confirm it worked correctly. This reinforced the importance of verifying actual resource state rather than assuming configuration matches intent, a useful lesson for real-world cloud security work.

## Scope & Limitations

This scanner checks for three specific, well-known misconfiguration patterns. A production-grade tool (like AWS Security Hub or AWS Trusted Advisor) would include dozens or hundreds of checks across many more services. This project demonstrates the core concept — automated, rule-based detection of cloud misconfigurations — end to end, on a smaller scale.
