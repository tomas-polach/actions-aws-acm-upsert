# AWS Certificate Upsert Github Action

Retrieves or creates a certificate in AWS Certificate Manager (ACM) for a list of given domain.
Supports role arns for cross account access.

## Usage Example

```yaml
name: Deploy

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Retrieve or create certificate
        id: retrieve-certificate
        uses: tomas-polach/aws-acm-upsert-action@v1
        with:
          domains: 'example.com,*.example.com'
          domain-role-arn: 'arn:aws:iam::123456789012:role/role-name' # optional
          certificate-region: 'us-east-1'
          certificate-role-arn: 'arn:aws:iam::123456789012:role/role-name' # optional
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

      # optional: use certificate arn in later steps (example bash script)
    - name: Use certificate arn
        run: |
        echo "Certificate ARN: ${{ steps.retrieve-certificate.outputs.certificate-arn }}"
```
