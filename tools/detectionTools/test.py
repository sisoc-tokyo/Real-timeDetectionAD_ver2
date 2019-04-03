import time, threading, json
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from flask import Flask, request
import sys

EVENT_ST="4769"
WARN="warning:ST without TGT"
#WARN="attack:test"
RESULT_NOTGT="attack: Golden Ticket is used"
RESULT_NORMAL="normal"
INDEX="realtime-*"
DOC_TYPE="doc"

def detect_golden(ip_src):
    ip_ptn='*'+ip_src+'*'
    es = Elasticsearch('10.0.19.112:9200')
    s = Search(using=es, index=INDEX)
    s = s[0:1]
    q = Q('match', indicator= WARN) & Q('match', event_id = EVENT_ST) & Q('match', event_data__IpAddress = ip_ptn)
    s1 = s.query(q)
    response = s1.execute()
    id=''
    index=''
    for h in response:
        id=h.meta.id
        index=h.meta.index
        #print(h.meta.id)

    if len(response) != 0:
        es.update(index=index, doc_type=DOC_TYPE, id=id, body={'doc': {'indicator': RESULT_NOTGT}})
        print(RESULT_NOTGT)
        return RESULT_NOTGT

    else:
        RESULT_NORMAL

if __name__ == '__main__':
    ip_src=sys.argv[1]
    result=detect_golden(ip_src)
    print(result)