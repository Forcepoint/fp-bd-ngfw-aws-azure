import asyncio
import threading

from AwsSecHub import amazon_security_hub_batch_upload, create_default_insights, setup_sec_hub, \
    enable_batch_import_findings
from CommonUtils import open_config_file, write_to_log, write_config_file, format_date_smc_filter
from MapToAsff import create_asff_object
import itertools

from smc import session
from smc_monitoring.monitors.logs import LogQuery
from smc_monitoring.wsocket import FetchAborted

from MapToCef import format_smc_logs_to_cef
from azure_agent_connector import send_sentinel_data

cfg = open_config_file()


def __setup_smc_query_filter(smc_filter):
    latest_date = cfg['latest-date']
    time_query = f' && default_false(($OrigTimestamp > time64("{latest_date}")))'

    if latest_date:
        return smc_filter + time_query
    else:
        return smc_filter


def run_query_and_upload():
    aws_integration = cfg.get('aws-integration', False)
    azure_integration = cfg.get('azure-integration', False)

    # Create default insights if they don't already exist - TODO move this step to configurator
    if aws_integration:
        threading.Thread(target=create_default_insights).start()
        setup_sec_hub()
        enable_batch_import_findings()

    default_filter = __setup_smc_query_filter(cfg['default-filter'])

    smc_url = cfg['host-ip'] + ':' + cfg['host-port']

    session.login(url=smc_url, api_key=cfg['client-api-key'])

    try:
        query = LogQuery(fetch_size=int(cfg['fetch-size']))

        translated_filter = query.add_translated_filter()

        # Create default filter specified in the config file
        translated_filter.update_filter(default_filter)

        # Query the SMC for events matching the filter and flatten the list of result-lists into a single list
        record_list = list(itertools.chain(*query.fetch_raw()))

        extra_filters_enabled = cfg['extra-filters-enabled']

        # Check to see if extra filters are enabled and if any are present before iterating over them and requesting
        # matching events from the SMC and appending to the original results list
        if bool(extra_filters_enabled):
            extra_filters = cfg['extra-filters']
            if bool(extra_filters):
                for log_filter in extra_filters:
                    translated_filter.update_filter(__setup_smc_query_filter(log_filter))
                    record_list.extend(list(itertools.chain(*query.fetch_raw())))

        if record_list:
            # Find the max date in the record list and store this to add to the filter for subsequent queries
            # to avoid uploading duplicates/wasting bandwidth. This value is written to the cfg.json file
            cfg['latest-date'] = format_date_smc_filter(max(item['Creation Time'] for item in record_list))
            write_config_file(cfg)

            loop = asyncio.get_event_loop()

            # Map to appropriate format and upload if integration is active
            if aws_integration:
                aws_task = loop.create_task(
                    amazon_security_hub_batch_upload(list(map(create_asff_object, record_list))))
                loop.run_until_complete(aws_task)

            if azure_integration:
                send_sentinel_data(list(map(format_smc_logs_to_cef, record_list)))

    # This catches any issues related to requesting events with a malformed filter
    except FetchAborted as exception:
        print(exception)
        write_to_log(exception)

    session.logout()
