import os
from os import system

from CommonUtils import open_config_file

if not os.path.exists('omsagent-1.12.15-0.universal.x64.sh'):
    system(open_config_file()['azure-agent-script'])
