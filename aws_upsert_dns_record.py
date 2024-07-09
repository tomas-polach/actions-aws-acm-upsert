import sys
import os
from time import sleep
import boto3


class DNSAndSSLCertManager:
    def __init__(
            self,
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

    @staticmethod
    def _assume_role(role_arn: str) -> tuple[str, str, str]:
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="DNSUpdateSession"
        )
        return (
            assumed_role['Credentials']['AccessKeyId'],
            assumed_role['Credentials']['SecretAccessKey'],
            assumed_role['Credentials']['SessionToken'],
        )

    def _get_hosted_zone_id(self, subdomain):
        # List all hosted zones
        hosted_zones = self.route53_client.list_hosted_zones_by_name()

        # Find the hosted zone ID for the given subdomain
        for zone in hosted_zones['HostedZones']:
            if subdomain.endswith(zone['Name'].rstrip('.')):
                return zone['Id'].split('/')[-1]

        raise Exception(f"No hosted zone found for subdomain: {subdomain}")

    def _upsert_cname_record(self, hosted_zone_id, subdomain: str, target: str):
        change_batch = {
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": subdomain,
                        "Type": "CNAME",
                        "TTL": 300,
                        "ResourceRecords": [
                            {
                                "Value": target
                            }
                        ]
                    }
                }
            ]
        }

        response = self.route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch=change_batch
        )

        return response

    def add_cname_record(self, subdomain, target):
        # Retrieve hosted zone ID
        hosted_zone_id = self._get_hosted_zone_id(subdomain)
        # Upsert CNAME record
        self._upsert_cname_record(hosted_zone_id, subdomain, target)


if __name__ == "__main__":
    # retrieve inputs
    domain = os.getenv('DOMAIN')
    target_domain = os.getenv('TARGET_DOMAIN')
    domain_role_arn = os.getenv('DOMAIN_ROLE_ARN')

    m = DNSAndSSLCertManager(domain_role_arn = os.getenv('DOMAIN_ROLE_ARN'))
    m.add_cname_record(domain, target_domain)
