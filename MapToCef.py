from format_cef import format_cef

from CommonUtils import datetime_string_to_object

"""Produces a CEF compliant message from the arguments.

       :parameter str vendor: Vendor part of the product type identifier
       :parameter str product: Product part of the product type identifier
       :parameter str product_version: Version part of the product type identifier
       :parameter str event_id: A unique identifier for the type of event being
           reported
       :parameter str event_name: A human-friendly description of the event
       :parameter int severity: Between 0 and 10 inclusive.
       :parameter dict extensions: key-value pairs for event metadata.
       """


def format_smc_logs_to_cef(record):
    result = format_cef(
        vendor='Forcepoint',
        product='NGFW',
        product_version='6.60',
        event_id=record['Event ID'],
        event_name=create_event_name(record),
        severity=normalize_severity_ngfw(record),
        extensions={
            'deviceAction': record.get('Action', 'N/A'),
            'sourceAddress': record.get('Src Addrs', '0.0.0.0'),
            'destinationAddress': record.get('Dst Addrs', '0.0.0.0'),
            'sourcePort': int(record.get('Src Port', 0)),
            'destinationPort': int(record.get('Dst Port', 0)),
            'applicationProtocol': record.get('Network Application', 'N/A'),
            'transportProtocol': record.get('IP Protocol', 'N/A'),
            'startTime': datetime_string_to_object(record['Creation Time']),
            'deviceEventCategory': record.get('Situation Type', 'N/A'),
            'deviceCustomString1': record.get('Rule Tag', 'N/A')
        }
    )
    return result


def create_event_name(record):
    return f"{record.get('Situation Type', 'N/A')}-{record.get('Situation', 'N/A')}-{record.get('Anomalies', 'N/A')}"


def normalize_severity_ngfw(record):
    switcher = {
        'Info': 1,
        'Low': 3,
        'High': 5,
        'Critical': 10
    }
    return switcher.get(record.get('Severity'), 0)
