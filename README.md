# Export NGFW events to AWS Security Hub

## Technical Overview

The purpose of this project is to allow the extraction of NGFW log data from the SMC and upload to AWS Security Hub
in its own ASFF format.

## Creating a filter

Open the SMC UI filter builder in the logs view, set up the filter as you require it and verify the results are correct
by querying in the logs view. Once you are satisfied with the results you can select all items in the filter view, 
right click them and choose 'Combine Filters'. You should now have a filter named 'Combined <x>'.
Right click on that filter and choose 'Show Expression Translation', a window will pop up with the filter in text form.
Copy that text exactly into either the `default-filter` (if none already exists) or into the `extra-filters` array
in the cfg.json. Each subsequent filter you add should be its own element in the `extra-filters` array.
e.g.: 
```
"extra-filters": [
    "(true && (default_false($Protocol == 17) 
        && default_false($Dport IN union(range(0, 65535)))))",
    "(default_false($AlertSeverity IN 
        union(union(8, 9, 10), union(5, 6, 7), union(2, 3, 4))))"
  ]
```
## Note

This service writes the response from all requests to a file called log.txt, if something doesn't seem to work 
please check there for 'Failed Findings' or any errors thrown from the service itself.
- If you see something like:
```
Failed to create query 
Invalid Expression.
``` 
this means that the filter
 you have supplied is malformed, please copy it exactly from the SMC filter tool.

## Prerequisites

- Python 3.6+
- AWS Security Hub access
- Enable and create SMC API client (to retrieve api key)
- cfg.json file with parameters filled (Sample supplied - cfg-sample.json)

## Dependencies
- smc-python-monitoring (pip install smc-python-monitoring)
- boto3 (pip install boto3)



## Related Documentation
- [SMC API Reference](https://www.websense.com/content/support/library/ngfw/v62/rfrnce/ngfw_620_rg_smc-api_a_en-us.pdf)
- [smc-python](https://smc-python.readthedocs.io/en/latest/) (General SMC-API-python docs)
- [smc-python-monitoring](https://smc-python.readthedocs.io/en/latest/pages/extensions.html) 
(Specific to Monitoring/Extracting log data)
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) (AWS client library)