from CommonUtils import open_config_file, datetime_to_iso8601_format

cfg = open_config_file()

product_arn = f"arn:aws:securityhub:{cfg['region_name']}:{cfg['AwsAccountId']}:product/forcepoint/forcepoint-ngfw"


def __normalize_severity_ngfw(record):
    switcher = {
        'INFORMATIONAL': 1,
        'LOW': 3,
        'HIGH': 5,
        'CRITICAL': 10
    }
    return switcher.get(record.get('Severity'), 0)


def __convert_severity_ngfw(record):
    switcher = {
        'Info': 'INFORMATIONAL',
        'Low': 'LOW',
        'High': 'HIGH',
        'Critical': 'CRITICAL'

    }
    return switcher[record]


def create_asff_object(record):
    return create_finding_object(record)


def create_finding_object(record):
    return {
        "AwsAccountId": cfg['AwsAccountId'],
        "ProductArn": product_arn,
        "Id": record.get('Event ID', None),
        "CreatedAt": datetime_to_iso8601_format(record['Creation Time']),
        "Description": create_description(record),
        "GeneratorId": record['Component ID'],
        "SchemaVersion": "2018-10-08",
        "Title": "Forcepoint NGFW",
        "Remediation": create_remediation_object(record),
        "Types": create_types_object(),
        "UpdatedAt": datetime_to_iso8601_format(record['Creation Time']),
        "Network": create_network_object(record),
        "Severity": create_severity_object(record),
        "Resources": create_resources_object(record)
    }


def create_description(record):
    return f"{record.get('Situation Type', 'N/A')}-{record.get('Situation', 'N/A')}-{record.get('Anomalies', 'N/A')}"


def create_types_object():
    return [
        'Unusual Behaviors/Network Flow/ForcepointNGFW'
    ]


def create_malware_object(record):
    return [
        {
            "Name": "string",
            "Path": "string",
            "State": "string",
            "Type": record['Situation']
        }
    ]


def create_remediation_object(record):
    return {
        "Recommendation": {
            "Text": record.get('Action', "N/A")
        }
    }


def create_network_object(record):
    return {
        "DestinationDomain": record.get('URL', "N/A")[:128],
        "DestinationIpV4": record.get('Dst Addrs', "0.0.0.0"),
        "DestinationPort": int(record.get('Dst Port', 0)),
        "Direction": "IN",
        "Protocol": record.get('IP Protocol', "N/A"),
        "SourceDomain": "N/A",
        "SourceIpV4": record.get('Src Addrs', "0.0.0.0"),
        "SourcePort": int(record.get('Src Port', 0))
    }


def create_severity_object(record):
    return {
        "Label": __convert_severity_ngfw(record.get('Severity', 'Info')).upper(),
        "Product": __normalize_severity_ngfw(record)
    }


def create_resources_object(record):
    return [
        {
            "Type": "Other",
            "Id": record.get('Sender', "N/A"),
            "Details": {
                "Other": {
                    "Sender Type": record.get('Sender Type', "N/A"),
                    "Type": record.get('Type', "N/A"),
                    "Facility": record.get('Facility', "N/A"),
                    "Source Interface": record.get('Src IF', "N/A"),
                    "Destination Interface": record.get('Dst IF', "N/A"),
                    "Information Message": record.get('Information Message', "N/A"),
                    "Data Type": record.get('Data Type', "N/A"),
                    "Network Application": record.get('Network Application', "N/A"),
                    "Data Identifier": record.get('Data Identifier', "N/A"),
                    "Rule Tag": record.get('Rule Tag', "N/A"),
                    "Action": record.get('Action', "N/A"),
                    "Vulnerability Reference": record.get('Vulnerability References', "N/A")
                }
            },
            "Tags": {
                "DataTags": record.get('Data Tags', "N/A")
            }
        }
    ]
