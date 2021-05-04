from os import system

from CommonUtils import open_config_file, write_config_file

cfg = open_config_file()


def send_sentinel_data(records, max_date):
    for record in records:
        cmd = f"logger -n localhost -P 514 -T `echo '{record.strip()}' | sed 's/\\=/\=/g'`"
        cmd = cmd.replace('"', "")
        system(cmd)
    cfg['latest-date'] = max_date
    write_config_file(cfg)
