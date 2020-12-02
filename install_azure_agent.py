from os import system

from CommonUtils import open_config_file

cfg = open_config_file()

system(cfg['azure-agent-script'])
