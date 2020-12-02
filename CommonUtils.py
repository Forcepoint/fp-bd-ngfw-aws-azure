import json
from datetime import datetime
from itertools import zip_longest

is_dev = False


def open_config_file():
    config_file_name = 'cfg-dev.json' if is_dev else 'cfg.json'
    with open(config_file_name) as config_file:
        return json.load(config_file)


def write_config_file(cfg):
    config_file_name = 'cfg-dev.json' if is_dev else 'cfg.json'
    with open(config_file_name, 'r+') as config:
        config.seek(0)
        config.write(json.dumps(cfg))
        config.truncate()


def open_insights_file():
    with open('aws-sechub-default-insights.json') as insights_file:
        return json.load(insights_file)


def open_insights_arn_file():
    with open('default-insights-arn.json') as insights_file:
        return json.load(insights_file)


def write_to_insights_arn_file(arns):
    with open('default-insights-arn.json', 'r+') as config:
        config.seek(0)
        config.write(json.dumps(arns))
        config.truncate()


def write_to_log(log_item):
    f = open('log.txt', 'a+')
    f.write(str(datetime.now()) + ': ' + str(log_item) + '\n')
    f.close()


def get_current_utc_datetime():
    return str(datetime.utcnow().replace(microsecond=0))


def datetime_to_iso8601_format(time):
    date_time_obj = datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
    return str(date_time_obj.strftime('%Y-%m-%dT%H:%M:%SZ'))


def datetime_string_to_object(time):
    return datetime.strptime(time, '%Y-%m-%d %H:%M:%S')


def format_date_smc_filter(date):
    date_time_obj = datetime.strptime(date, '%Y-%m-%d %H:%M:%S')
    return str(date_time_obj.strftime('%Y%m%d.%H:%M:%S.000'))


# Split a list into chunks of the specified size
def chunker(iterable, n, fill_value=None):
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fill_value)
