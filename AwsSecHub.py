from collections import deque

import boto3
from botocore.exceptions import EndpointConnectionError

from CommonUtils import open_config_file, write_to_log, chunker, open_insights_file, open_insights_arn_file, \
    write_to_insights_arn_file

cfg = open_config_file()


def aws_connection():
    return boto3.client('securityhub',
                        aws_access_key_id=cfg['aws_access_key_id'],
                        aws_secret_access_key=cfg['aws_secret_access_key'],
                        region_name=cfg['region_name']
                        )


aws_integration = cfg.get('aws-integration', False)

if aws_integration:
    client = aws_connection()


def enable_batch_import_findings():
    product_arn = f"arn:aws:securityhub:{cfg['region_name']}:{cfg['AwsAccountId']}:product/forcepoint/forcepoint-ngfw"
    try:
        client.enable_import_findings_for_product(ProductArn=product_arn)
    except client.exceptions.ResourceConflictException as exception:
        write_to_log(exception)


def setup_sec_hub():
    try:
        client.enable_security_hub()
    except client.exceptions.ResourceConflictException as exception:
        write_to_log(exception)


async def amazon_security_hub_batch_upload(asff_findings):
    try:
        # The max batch size allowed by boto upload is 100
        chunked_values = chunker(asff_findings, 100)

        queue = deque(__sanitise_list_input(chunked_values))

        # Upload to AWS Security Hub and write the response to a log file
        while queue:
            write_to_log(client.batch_import_findings(Findings=queue.popleft()))

    except EndpointConnectionError as exception:
        write_to_log(exception)


# Create the default insights if they haven't already been created
def create_default_insights():
    try:
        insight_arns = open_insights_arn_file()
        aws_insight_arns = retrieve_insight_arns_as_list()

        if insight_arns and set(insight_arns).issubset(set(aws_insight_arns)):
            # The insights already exist on AWS
            return
        else:
            # Create the default insights
            response_list = list()
            get_insights = open_insights_file()
            for insight in get_insights:
                response = client.create_insight(
                    Name=insight['Name'],
                    Filters=insight['Filters'],
                    GroupByAttribute=insight['GroupByAttribute'])

                response_list.append(response['InsightArn'])

            write_to_insights_arn_file(response_list)
    except client.exceptions.LimitExceededException as exc:
        write_to_log(exc)
    except EndpointConnectionError as exception:
        write_to_log(exception)


# Remove all NoneTypes
def __sanitise_list_input(chunked_list):
    sanitised_list = []
    for chunk in chunked_list:
        sanitised_list.append([i for i in chunk if i])

    return sanitised_list


def retrieve_insight_arns_as_list():
    get_insights = client.get_insights()['Insights']

    aws_insight_arns = list()

    for item in get_insights:
        aws_insight_arns.append(item['InsightArn'])
    return aws_insight_arns
