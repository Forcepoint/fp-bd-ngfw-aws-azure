from cefevent import CEFEvent
from CommonUtils import datetime_to_timestamp

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
    c = CEFEvent()

    c.set_field('name', 'Event Name')
    c.set_field('deviceVendor', 'Forcepoint')
    c.set_field('deviceProduct', 'NGFW')
    c.set_field('deviceVersion', '6.60')
    c.set_field('name', create_event_name(record))
    c.set_field('severity', normalize_severity_ngfw(record), )
    c.set_field('signatureId', record['Event ID'])
    c.extensions = {
        'applicationProtocol': record.get('Network Application', 'N/A'),
        'deviceCustomString1': record.get('Rule Tag', 'N/A'),
        'src': record['Src Addrs'],
        'destinationAddress': record.get('Dst Addrs', '0.0.0.0'),
        'sourcePort': int(record.get('Src Port', 0)),
        'destinationPort': int(record.get('Dst Port', 0)),
        'deviceAction': record.get('Action', 'Action'),
        'transportProtocol': record.get('IP Protocol', 'TProto'),
        'startTime': datetime_to_timestamp(record['Creation Time']),
        'deviceEventCategory': record.get('Situation Type', 'ECategory'),
    }

    return c.build_cef()


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
