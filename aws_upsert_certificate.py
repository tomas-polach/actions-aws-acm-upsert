import os
from time import sleep
import boto3


class DNSAndSSLCertManager:
    def __init__(
            self,
            certificate_region: str,
            certificate_role_arn: str | None = None,
            domain_role_arn: str | None = None,
    ):
        if domain_role_arn is None:
            self.route53_client = boto3.client('route53')
        else:
            # if domain is registered in another aws account, assume role
            access_key_id, secret_access_key, session_token = self._assume_role(domain_role_arn)
            self.route53_client = boto3.client(
                'route53',
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                aws_session_token=session_token,
            )

        if certificate_role_arn is None:
            self.acm_client = boto3.client('acm', region_name=certificate_region)
        else:
            # if cert is created in another aws account, assume role
            access_key_id, secret_access_key, session_token = self._assume_role(certificate_role_arn)
            self.acm_client = boto3.client(
                'acm',
                region_name=certificate_region,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                aws_session_token=session_token,
            )

    @staticmethod
    def _assume_role(role_arn: str) -> tuple[str, str, str]:
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="DNSUpdateSession",
        )
        return (
            assumed_role['Credentials']['AccessKeyId'],
            assumed_role['Credentials']['SecretAccessKey'],
            assumed_role['Credentials']['SessionToken'],
        )

    def _get_hosted_zone_id(self, domain):
        # List all hosted zones
        hosted_zones = self.route53_client.list_hosted_zones_by_name()

        # Find the hosted zone ID for the given domain
        for zone in hosted_zones['HostedZones']:
            if domain.rstrip('.').endswith(zone['Name'].rstrip('.')):
                return zone['Id'].split('/')[-1]

        raise Exception(f"No hosted zone found for domain: {domain}")

    @staticmethod
    def _match_domain(domain, pattern):
            domain_parts = domain.split('.')
            pattern_parts = pattern.split('.')

            # If the number of parts doesn't match, it's not a match
            if len(domain_parts) != len(pattern_parts):
                return False

            # Check each part
            for d_part, p_part in zip(domain_parts, pattern_parts):
                if p_part == '*':
                    continue
                if d_part != p_part:
                    return False
            return True

    @staticmethod
    def _check_if_domains_are_in_cert(domains: list[str], cert_domains: list[str]) -> bool:
        for source in domains:
            if not any(DNSAndSSLCertManager._match_domain(source, target) for target in cert_domains):
                return False
        return True

    def get_or_create_ssl_cert(self, domains: list[str]) -> str:
        # List all certificates
        paginator = self.acm_client.get_paginator('list_certificates')
        cert_arn = None
        for page in paginator.paginate(CertificateStatuses=['PENDING_VALIDATION', 'ISSUED']):
            for cert in page['CertificateSummaryList']:
                cert_details = self.acm_client.describe_certificate(CertificateArn=cert['CertificateArn'])
                cert_domains = cert_details['Certificate']['SubjectAlternativeNames']
                if DNSAndSSLCertManager._check_if_domains_are_in_cert(domains, cert_domains):
                    print(f"Found existing certificate: {cert['CertificateArn']}")
                    cert_arn = cert['CertificateArn']
                    break

        if cert_arn is not None:
            # check if the certificate is already validated
            cert_details = self.acm_client.describe_certificate(CertificateArn=cert_arn)
            if cert_details['Certificate']['Status'] == 'ISSUED':
                print(f"Certificate is already validated: All good.")
                return cert_arn

        if cert_arn is None:
            # If no suitable certificate found, create a new one
            if len(domains) == 1:
                response = self.acm_client.request_certificate(
                    DomainName=domains[0],
                    ValidationMethod='DNS',
                )
            else:
                response = self.acm_client.request_certificate(
                    DomainName=domains[0],
                    ValidationMethod='DNS',
                    SubjectAlternativeNames=domains[1:],
                )
            cert_arn = response['CertificateArn']
            print(f"Requested new certificate: {cert_arn}")

        # Wait for required DNS validation records to be available by certificate creation API (takes ca 5-15 seconds)
        validation_options = None
        while validation_options is None:
            cert_details = self.acm_client.describe_certificate(CertificateArn=cert_arn)
            if 'DomainValidationOptions' in cert_details['Certificate'] and len(cert_details['Certificate']['DomainValidationOptions']) > 0:
                validation_options = cert_details['Certificate']['DomainValidationOptions']
                print(f"DNS validation set available.")
            else:
                print(f"Waiting for DNS validation set ...")
                sleep(5)

        # create DNS validation records
        validation_records = []
        for option in validation_options:
            if 'ResourceRecord' in option:
                validation_record = option['ResourceRecord']
                print(f"Creating DNS validation record: {validation_record}")
                validation_records.append(validation_record)
                hosted_zone_id = self._get_hosted_zone_id(validation_record['Name'])
                change_batch = {
                    "Changes": [{
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": validation_record['Name'],
                            "Type": validation_record['Type'],
                            "TTL": 300,
                            "ResourceRecords": [
                                {
                                    "Value": validation_record['Value']
                                }
                            ]
                        }
                    }]
                }
                self.route53_client.change_resource_record_sets(
                    HostedZoneId=hosted_zone_id,
                    ChangeBatch=change_batch
                )

        # Wait for the certificate to be validated
        print(f"Waiting for certificate {cert_arn} to be validated...")
        waiter = self.acm_client.get_waiter('certificate_validated')
        try:
            waiter.wait(CertificateArn=cert_arn)
            print(f"Certificate {cert_arn} successfully validated.")
        except Exception as e:
            print(f"Certificate validation failed: {e}")

        # remove validation record names
        for validation_records in validation_records:
            print(f"Cleanup: Deleting DNS validation record: {validation_records['Name']}")
            hosted_zone_id = self._get_hosted_zone_id(validation_records['Name'])
            batch = {
                "Changes": [{
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": validation_records['Name'],
                        "Type": "CNAME",
                        "TTL": 300,
                        "ResourceRecords": [
                            {
                                "Value": validation_record['Value']
                            }
                        ]
                    }
                }]
            }
            self.route53_client.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch=batch
            )


        return cert_arn


if __name__ == "__main__":
    # check if AWS_DEFAULT_REGION env var is set
    if os.getenv('AWS_DEFAULT_REGION') is None:
        raise Exception("Error: AWS_DEFAULT_REGION env var is not set.")

    # retrieve inputs
    domains = os.getenv('DOMAINS').split(',')
    domain_role_arn = os.getenv('DOMAIN_ROLE_ARN')
    certificate_role_arn = os.getenv('CERTIFICATE_ROLE_ARN')
    certificate_region = os.getenv('AWS_DEFAULT_REGION')

    m = DNSAndSSLCertManager(
        certificate_region=certificate_region,
        certificate_role_arn=certificate_role_arn if certificate_role_arn != '' else None,
        domain_role_arn=domain_role_arn if domain_role_arn != '' else None,
    )
    cert_arn = m.get_or_create_ssl_cert(domains)

    # return github action outputs:
    # Write the output to the GITHUB_OUTPUT environment file
    with open(os.getenv('GITHUB_OUTPUT'), 'a') as f:
        print(f"certificate-arn={cert_arn}", file=f)
