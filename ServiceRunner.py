from CommonUtils import open_config_file
from QuerySmc import run_query_and_upload
import time

cfg = open_config_file()

if __name__ == '__main__':
    time_to_run = int(cfg.get('run-interval', 900)) if int(cfg.get('run-interval', 900)) > 300 else 300
    while True:
        run_query_and_upload()
        time.sleep(time_to_run)
