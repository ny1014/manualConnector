import json
import logging
from typing import List
import urllib.parse

import custom_connector_sdk.lambda_handler.requests as requests
import custom_connector_sdk.lambda_handler.responses as responses
import custom_connector_example.handlers.validation as validation
import custom_connector_example.handlers.salesforce as salesforce
from custom_connector_sdk.lambda_handler.handlers import RecordHandler
from custom_connector_sdk.connector.fields import WriteOperationType, FieldDataType
from custom_connector_sdk.connector.context import ConnectorContext
from custom_connector_example.query.builder import QueryObject, build_query

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

SALESFORCE_OBJECT_API_FORMAT = '{}services/data/{}/sobjects/{}'
SALESFORCE_QUERY_FORMAT = '{}services/data/{}/query?q={}'
# [Organization URI]/api/data/v9.2/accounts?$select=name
D365_QUERY_FORMAT= '{}api/USERINFO_URL_FORMATdata/{}/{}'
import boto3

from custom_connector_sdk.connector.auth import ACCESS_TOKEN
from dynamics365crm.client import Client
# SALESFORCE_SOBJECTS_URL_FORMAT = '{}services/data/{}/sobjects'
# SALESFORCE_SOBJECT_DESCRIBE_URL_FORMAT = '{}services/data/{}/sobjects/{}/describe'
# For production instances, https://login.salesforce.com/services/Soap/c/xx.0/0DF300000000xxS
# Or, if MyDomain is enabled on the org, you can use, 
#  https://MyDomain.my.salesforce.com/services/Soap/c/xx.0/0DF300000000xxS 

# For example, to retrieve basic information about an Account object in version 58.0 use 
# https://MyDomainName.my.salesforce.com/services/data/v58.0/sobjects/Account.
# Salesforce response keys
RECORDS_KEY = 'records'
SUCCESS_KEY = 'success'
ID_KEY = 'id'
ERRORS_KEY = 'errors'

def get_query_string(query_object: QueryObject) -> str:
    """Build query string and encode special characters."""
    return urllib.parse.quote(build_query(query_object))
# s = '日本語'

# s_quote = urllib.parse.quote(s)

# print(s_quote)
# %E6%97%A5%E6%9C%AC%E8%AA%9E
def get_query_connector_response(query_object: QueryObject, connector_context: ConnectorContext) ->\
        salesforce.SalesforceResponse:
    """Build query string and make GET request to Salesforce"""
    query = get_query_string(query_object)
    # {instanceurl}services/data/{version}/query?q={query}
    request_uri = salesforce.build_salesforce_request_uri(connector_context, D365_QUERY_FORMAT, query) 
    https_client = salesforce.get_salesforce_client(connector_context)
    return https_client.rest_get(request_uri)

def parse_query_response(json_response: str) -> List[str]:
    """Parse JSON response from Salesforce query to a list of records."""
    parent_object = json.loads(json_response)

    if parent_object.get(RECORDS_KEY) is not None:
        return [json.dumps(record) for record in parent_object.get(RECORDS_KEY)]
    return []

def parse_write_response(json_response: str) -> responses.WriteRecordResult:
    """Convert JSON response from Salesforce write to a WriteRecordResult."""
    parent_object = json.loads(json_response)
    return responses.WriteRecordResult(is_success=salesforce.get_boolean_value(parent_object, SUCCESS_KEY),
                                       record_id=salesforce.get_string_value(parent_object, ID_KEY),
                                       error_message=str(parent_object.get(ERRORS_KEY)))

def get_value_from_data(record_json: dict, key: str) -> str:
    try:
        if record_json is None:
            raise ValueError("JSON parse error")
        if key not in record_json:
            raise ValueError(key + " key is missing from JSON record but is required")

        record_id = record_json[key]
        if not record_id:
            raise ValueError("Invalid value for object identifier key " + key)

        return record_id
    except ValueError as e:
        LOGGER.error("Exception while obtaining object identifier value from patch data record")
        raise e

def get_salesforce_write_response(record: str, request: requests.WriteDataRequest):
    record_json = json.loads(record)
    request_uri = salesforce.build_salesforce_request_uri(request.connector_context,
                                                          SALESFORCE_OBJECT_API_FORMAT,
                                                          request.entity_identifier)
    if request.operation is WriteOperationType.INSERT:
        return salesforce.get_salesforce_client(request.connector_context) \
            .rest_post(request_uri, json.dumps(record_json))
    elif request.operation is WriteOperationType.UPDATE:
        if len(request.id_field_names) != 1:
            raise ValueError("A single Id field name is required for UPDATE operations in Salesforce")
        record_id_key = request.id_field_names[0]
        record_id = get_value_from_data(record_json, record_id_key)
        del record_json[record_id_key]
        request_uri = request_uri + '/' + record_id

        return salesforce.get_salesforce_client(request.connector_context) \
            .rest_patch(request_uri, json.dumps(record_json))
    elif request.operation is WriteOperationType.UPSERT:
        if len(request.id_field_names) != 1:
            raise ValueError("A single Id field name is required for UPSERT operations in Salesforce")
        upsert_external_id_key = request.id_field_names[0]
        upsert_external_id = get_value_from_data(record_json, upsert_external_id_key)
        del record_json[upsert_external_id_key]
        request_uri = request_uri + '/' + upsert_external_id_key + '/' + upsert_external_id

        return salesforce.get_salesforce_client(request.connector_context) \
            .rest_patch(request_uri, json.dumps(record_json))
    else:
        raise ValueError('WriteOperationType' + request.operation.name + ' is not supported.')

class SalesforceRecordHandler(RecordHandler):
    # """Salesforce Record handler."""
    # def retrieve_data(self, request: requests.RetrieveDataRequest) -> responses.RetrieveDataResponse:
    #     error_details = validation.validate_request_connector_context(request)
    #     if error_details:
    #         LOGGER.error('RetrieveData request failed with ' + str(error_details))
    #         return responses.RetrieveDataResponse(is_success=False, error_details=error_details)

    #     query_object = QueryObject(s_object=request.entity_identifier,
    #                                selected_field_names=request.selected_field_names,
    #                                id_field_name=request.id_field_name,
    #                                fields=request.ids,
    #                                data_type=FieldDataType.Struct.name)

    #     salesforce_response = get_query_connector_response(query_object, request.connector_context)
    #     error_details = salesforce.check_for_errors_in_salesforce_response(salesforce_response)

    #     if error_details:
    #         return responses.RetrieveDataResponse(is_success=False, error_details=error_details)

    #     return responses.RetrieveDataResponse(is_success=True,
    #                                           records=parse_query_response(salesforce_response.response))

    # def write_data(self, request: requests.WriteDataRequest) -> responses.WriteDataResponse:
    #     error_details = validation.validate_write_data_request(request)
    #     if error_details:
    #         LOGGER.error('WriteData request failed with ' + str(error_details))
    #         return responses.WriteDataResponse(is_success=False, error_details=error_details)

    #     write_record_results = []
    #     for record in request.records:
    #         salesforce_response = get_salesforce_write_response(record, request)
    #         error_details = salesforce.check_for_errors_in_salesforce_response(salesforce_response)

    #         if error_details:
    #             return responses.WriteDataResponse(is_success=False, error_details=error_details)
    #         if salesforce_response.response:
    #             write_record_results.append(parse_write_response(salesforce_response.response))

    #     # Salesforce UPDATE operation does not return a response. In this case we succeed unless there are errors found.
    #     if request.operation is not WriteOperationType.UPDATE and len(write_record_results) == 0:
    #         return responses.WriteDataResponse(is_success=False)
    #     else:
    #         return responses.WriteDataResponse(is_success=True,
    #                                            write_record_results=write_record_results)

    def retrieve_data(
        self, request: requests.RetrieveDataRequest
    ) -> responses.RetrieveDataResponse:
        print("RecordHandler::retrieve_data")
        record_list = []
        return responses.RetrieveDataResponse(is_success=True, records=record_list)

    def write_data(
        self, request: requests.WriteDataRequest
    ) -> responses.WriteDataResponse:
        print("RecordHandler::write_data")
        write_record_results = []

        return responses.WriteDataResponse(
            is_success=True, write_record_results=write_record_results
        )

    def query_data(self, request: requests.QueryDataRequest) -> responses.QueryDataResponse:
        # error_details = validation.validate_request_connector_context(request)
        # if error_details:
        #     LOGGER.error('QueryData request failed with ' + str(error_details))
        #     return responses.QueryDataResponse(is_success=False, error_details=error_details)



        secrets_manager = boto3.client('secretsmanager')
        # secret_arn
        secret = secrets_manager.get_secret_value(SecretId= request.connector_context.credentials.secret_arn)
        access_token = json.loads(secret["SecretString"])[ACCESS_TOKEN]
        LOGGER.error(f'hey!test access_token = {access_token}')
        client = Client("https://org1deca345.crm7.dynamics.com", access_token=access_token)
        list_accounts = client.get_accounts()
        LOGGER.error(f'hey!test list_contacts = {list_accounts}')
        res =  [json.dumps(record) for record in list_accounts['value']]
        return responses.QueryDataResponse(is_success=True,
                                           records=res)
        # api = 'https://org1deca345.crm7.dynamics.com/api/data/v9.2/accounts'

        # query_object = QueryObject(s_object=request.entity_identifier,
        #                            selected_field_names=request.selected_field_names,
        #                            filter_expression=request.filter_expression,
        #                            entity_definition=request.connector_context.entity_definition)

        # https_client = salesforce.get_salesforce_client(request.connector_context)
        # https_client.rest_get(api)

# query_object
        # salesforce_response =  https_client.rest_get(api)
        
        # LOGGER.error(f'hey!test response = {salesforce_response}')
        # error_details = salesforce.check_for_errors_in_salesforce_response(salesforce_response)





        # if error_details:
        #     return responses.QueryDataResponse(is_success=False, error_details=error_details)

      
