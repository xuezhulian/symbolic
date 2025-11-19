# from elasticsearch import Elasticsearch

# 国内符号表新集群地址
ES_SYMBOL_TABLE_ADDR_NEW = [
    "10.36.102.11:9244",
    "10.36.102.17:9244",
    "10.36.101.48:9244",
    "10.38.116.52:9256",
    "10.38.108.51:9256",
    "10.38.116.52:9258",
    "10.38.108.51:9258",
    "10.38.111.50:9289",
    "10.38.118.53:9289",
    "10.38.111.50:9291",
    "10.38.118.53:9291",
    "10.36.132.34:9289",
    "10.38.57.47:9289",
    "10.36.132.34:9290",
    "10.38.57.47:9290",
    "10.36.141.187:9233",
    "10.36.141.187:9234",
    "10.36.145.186:9233",
    "10.36.145.186:9234",
    "10.36.84.42:9233",
    "10.36.84.42:9234"
]
# ES_SYMBOL_TABLE_ADDR_NEW_USER = "keepSymbol"
# ES_SYMBOL_TABLE_ADDR_NEW_PASSWORD = "iHXVUmT3oT"

# es_client = Elasticsearch(ES_ADDR_APP_TEST) "android_native_symbol*"
# es_client = Elasticsearch(ES_SYMBOL_TABLE_ADDR_NEW)

def query_es(uuid, offset):
    pass
    # body = {
    #     'size': 1,
    #     'query': {
    #         "bool": {
    #             "must": [
    #                 {
    #                     'range': {
    #                         'start_addr': {
    #                             'lte': offset
    #                         }
    #                     }
    #                 },
    #                 {
    #                     'range': {
    #                         'end_addr': {
    #                             'gt': offset
    #                         }
    #                     }
    #                 },
    #                 {'term': {
    #                     'uuid.keyword': uuid,
    #                 }
    #                 },
    #             ]
    #         }
    #     }
    # }

    # response = es_client.search(f'ios_symbol_{uuid[0]}_2023', body=body, request_timeout=10)
    # result = [hit['_source'] for hit in response['hits']['hits']]
    # if result:
    #     return result[0]
