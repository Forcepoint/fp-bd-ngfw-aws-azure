import json
import re


def handle_extra_filters(cfg):
    print('Your current extra filters are: ')
    for index, extra_filter in enumerate(cfg['extra-filters']):
        print(str(index + 1) + ' : ' + extra_filter)

    action = 0

    while action != 3:
        print()
        print('Do you want to: ')
        print('1: Add a filter?: ')
        print('2: Remove a filter?: ')
        print('3: Skip: ')
        action = input()

        if int(action) == 1:
            print('Enter the filter you would like to add: ', end='')
            filter_to_add = input()
            if filter_to_add:
                filter_list = list(cfg['extra-filters'])
                filter_list.append(filter_to_add)
                cfg['extra-filters'] = filter_list

        elif int(action) == 2:
            filter_list = list(cfg['extra-filters'])

            if not filter_list:
                print(Fore.LIGHTRED_EX + "You don't have any extra filters")
                return cfg

            print('Enter the index of the filter you would like to remove: ', end='')
            index = input()

            if int(index) < len(filter_list):
                del filter_list[int(index) - 1]
                cfg['extra-filters'] = filter_list

                print('Your updated extra filters are: ')
                for index, extra_filter in enumerate(cfg['extra-filters']):
                    print(Fore.LIGHTRED_EX + str(index + 1) + ' : ' + extra_filter)
            else:
                print(Fore.LIGHTRED_EX + 'index not within range')

        else:
            return cfg

    return cfg


with open('cfg.json', 'r+') as config:
    cfg_file = None
    # Print out header
    print('-' * 13)
    print('SMC to AWS Security hub (Forcepoint 2020)')
    print('-' * 13)

    # Get variables
    print()
    print('Are you integrating with Azure Sentinel?: (y/n)', end='')
    azure_integration = input()
    print('Are you integrating with AWS Security Hub?: (y/n) ', end='')
    aws_integration = input()
    print('What is the IP address for the SMC install?: (Please prefix with http(s)://)', end='')
    host_ip = input()
    print('On which port?: ', end='')
    host_port = input()
    print('What is the API key for the SMC?: ', end='')
    client_api_key = input()
    print('What is the interval between runs of the service? (in seconds, minimum 300 (5 mins): ', end='')
    run_interval = input()
    print('What is the default query size?: ', end='')
    default_query_size = input()
    print('What is the default query filter?: ', end='')
    default_query = input()
    print('Would you like to enable extra filters? (y/n): ', end='')
    extra_filters = input()

    if extra_filters == 'y':
        cfg_file = handle_extra_filters(json.load(config))

    if aws_integration:
        print('What is your AWS account ID?: ', end='')
        aws_account_id = input()
        print('What is the AWS access key ID?: ', end='')
        access_key_id = input()
        print('What is the AWS secret access key?: ', end='')
        secret_access_key = input()
        print('What is the AWS region?: ', end='')
        aws_region = input()

    if azure_integration:
        print('What is the data connector command from Azure Sentinel?: ', end='')
        azure_agent_script = input()

    # Write out configuration file
    print()
    print('Writing configuration...')

    if not cfg_file:
        cfg_file = json.load(config)

    cfg_file['azure-integration'] = True if azure_integration == 'y' else False
    cfg_file['aws-integration'] = True if aws_integration == 'y' else False
    cfg_file['host-ip'] = host_ip if re.findall('http[s]?://', host_ip) else 'http://' + host_ip
    cfg_file['host-port'] = host_port
    cfg_file['client-api-key'] = client_api_key
    cfg_file['run-interval'] = run_interval if run_interval != '' else None
    cfg_file['fetch-size'] = default_query_size if default_query_size != '' else None
    cfg_file['default-filter'] = default_query
    cfg_file['extra-filters-enabled'] = True if extra_filters == 'y' else False

    if aws_integration:
        cfg_file['AwsAccountId'] = aws_account_id
        cfg_file['aws_access_key_id'] = access_key_id
        cfg_file['aws_secret_access_key'] = secret_access_key
        cfg_file['region_name'] = aws_region

    if azure_integration:
        cfg_file['azure-agent-script'] = azure_agent_script

    config.seek(0)
    config.write(json.dumps(cfg_file))
    config.truncate()

    print()
    print('Configuration successfully written!')
    print()
