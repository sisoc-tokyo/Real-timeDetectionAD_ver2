import time, threading, json
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from flask import Flask, request
import detect_golden

def checkticket(ip_src, cipher, msg_type, timestamp):

    time.sleep(3)

    es = Elasticsearch('10.0.19.112:9200')
    s = Search(using=es, index="cipher-*")
    s = s[0:10000]

    if msg_type == 12:
        q = Q('match', layers__kerberos_msg_type=11) & Q('match', layers__ip_dst=ip_src) & Q('match', layers__kerberos_cipher__keyword=cipher)

    if msg_type == 14:
        q = (Q('match', layers__kerberos_msg_type= 11) | Q('match', layers__kerberos_msg_type= 13)) & Q('match', layers__ip_dst = ip_src) & Q('match', layers__kerberos_cipher__keyword = cipher)
    s1 = s.query(q)
    response = s1.execute()
    if len(response) != 0:
        print('normal')

    else:
        qtime = Q('range', timestamp={'gte': int(timestamp), 'lte': int(timestamp) + 1000}) & Q('match', layers__ip_dst = ip_src) & Q('match', layers__kerberos_error_code = 32)
        s2 = s.query(qtime)
        response2 = s2.execute()
        if len(response2) != 0:
            print('normal')

        else:
            s = Search(using=es, index="packet-*")
            s = s[0:10000]
            qsilver = Q('match', layers__kerberos_cipher__keyword=cipher)
            s3 = s.query(qsilver)
            response3 = s3.execute()
            
            for h in response3:
                id = h.meta.id
                index = h.meta.index
                if msg_type == 12:
                    print('Golden ticket was used on ' + str(ip_src))
                    detect_golden.detect_golden(ip_src)
                    es.update(index=index, doc_type='doc', id=id,
                              body={'doc': {'indicator': 'attack: Golden Ticket is used'}})
                if msg_type == 14:
                    es.update(index=index, doc_type='doc', id=id,
                              body={'doc': {'indicator': 'attack: Silver Ticket is used'}})
                    print('Silver ticket was used on ' + str(ip_src))

app = Flask(__name__)
@app.route('/tsharkmsg', methods=['POST'])
def tsharkmsg():

    message = request.form.get('message', None)
    message = message.strip("'")

    try:
        message = json.loads(message)
    except:
        with open('parse_error.log', 'a') as f:
            print(message, file=f)
        return 'parse_error'

    if int(message['layers']['kerberos_msg_type'][0]) == 12:
        ip_src = message['layers']['ip_src'][0]
        cipher = message['layers']['kerberos_cipher'][0]
        timestamp = message['timestamp']
        msg_type = 12
        t = threading.Thread(target=checkticket, args=([ip_src, cipher, msg_type, timestamp]))
        t.start()
        return 'normal'

    elif int(message['layers']['kerberos_msg_type'][0]) == 14:
        ip_src = message['layers']['ip_src'][0]
        cipher = message['layers']['kerberos_cipher'][0]
        timestamp = message['timestamp']
        msg_type = 14
        t = threading.Thread(target=checkticket, args=([ip_src, cipher, msg_type, timestamp]))
        t.start()
        return 'normal'
    else:
        return 'normal'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port = 5001, threaded = True)
