import time, threading, json
from datetime import datetime, timezone
from flask import Flask, request
import update_es, send_alert
import InputLog
import mysql.connector
import atexit
from identify_attack import identify_attack
from signature_detection import SignatureDetector

try:
    # Search old cipher from SQL.
    def checkticket(ip_src, cipher, msg_type, timestamp):
        conn = mysql.connector.connect(user='root', host='localhost', password='Passw0rd!', database='kerberos')
        cur = conn.cursor(buffered=True)
        try:
            time.sleep(1)

            if msg_type == 12:
                query = 'SELECT ip_src, kerberos_cipher, timestamp FROM cipher_table WHERE (msg_type = 11 OR msg_type = 13) AND ip_dst = INET_ATON(%s) AND kerberos_cipher = %s'
                cur.execute(query, (ip_src, cipher))
                curfet = cur.fetchall()

            elif msg_type == 14:
                query = 'SELECT ip_src, kerberos_cipher, timestamp FROM cipher_table WHERE msg_type = 13 AND ip_dst = INET_ATON(%s) AND kerberos_cipher = %s'
                cur.execute(query, (ip_src, cipher))
                curfet = cur.fetchall()

            for res in curfet:
                print(res[1])

            if cur.rowcount != 0:
                print('matched with old cipher at ' + str(timestamp))

            else:
                #Check TKT Expire
                query = 'SELECT * FROM cipher_table WHERE timestamp BETWEEN %s AND %s AND ip_dst = INET_ATON(%s) AND error_code = 32;'
                cur.execute(query, (timestamp, str(int(timestamp) + 1000), ip_src))

                if cur.rowcount != 0:
                    print('TKT Expired at ' + str(timestamp))

                else:
                    with open('./detected_ticket.log', mode='a') as f:
                        utctime = datetime.fromtimestamp(int(timestamp[:10]), timezone.utc)
                        if msg_type == 12:
                            f.write('Golden ticket was used on ' + str(ip_src) + ' at ' + str(utctime) + ' ' + str(cipher) + '\n')
                            print('Golden ticket was used on ' + str(ip_src) + ' at ' + str(utctime))
                            tactics = identify_attack.identify_tactics(SignatureDetector.RESULT_NOTGT, None)
                            send_alert.Send_alert(SignatureDetector.RESULT_NOTGT+","+tactics, datetime=utctime, ip_src=ip_src, eventid='-', accountname='-',
                                                  clientaddr='-', servicename='-', processname='-', objectname='-',
                                                  sharedname='-')

                        if msg_type == 14:
                            print('Silver ticket was used on ' + str(ip_src) + ' at ' + str(utctime))
                            f.write('Silver ticket was used on ' + str(ip_src) + ' at ' + str(utctime) + ' ' + str(cipher) + '\n')
                            tactics = identify_attack.identify_tactics(SignatureDetector.RESULT_SILVER, None)
                            send_alert.Send_alert(SignatureDetector.RESULT_SILVER+","+tactics, datetime=utctime, ip_src=ip_src, eventid='-', accountname='-',
                                                  clientaddr='-', servicename='-', processname='-', objectname='-',
                                                  sharedname='-')

                    if msg_type == 12:
                        n = 0
                        update_flag_event = True
                        while update_flag_event:
                            update_flag_event = update_es.update_event(ip_src)
                            time.sleep(1)
                            n += 1
                            if n >= 2:
                                break

                    n = 0
                    update_flag_packet = True
                    while update_flag_packet:
                        update_flag_packet = update_es.update_packet(cipher)
                        time.sleep(1)
                        n += 1
                        if n >= 2:
                            break
        finally:
            cur.close()
            conn.close()

    # Insert msg_type 11 or 13 data into SQL.
    def sqlinput_kereberos_msg(ip_src, ip_dst, cipher, msg_type, timestamp):
        conn = mysql.connector.connect(user='root', host='localhost', password='Passw0rd!', database='kerberos')
        cur = conn.cursor(buffered=True)
        try:
            query = 'INSERT INTO cipher_table(ip_src, ip_dst, kerberos_cipher, msg_type, timestamp) VALUES (INET_ATON(%s), INET_ATON(%s), %s, %s, %s)'
            cur.execute(query, (ip_src, ip_dst, cipher, msg_type, timestamp))
            conn.commit()
        finally:
            cur.close()
            conn.close()

    def sqlinput_kereberos_err(ip_src, ip_dst, timestamp):
        conn = mysql.connector.connect(user='root', host='localhost', password='Passw0rd!', database='kerberos')
        cur = conn.cursor(buffered=True)
        try:
            query = 'INSERT INTO cipher_table (ip_src, ip_dst, error_code, timestamp) VALUES (INET_ATON(%s), INET_ATON(%s), %s, %s)'
            cur.execute(query, (ip_src, ip_dst, 32, timestamp))
            conn.commit()
        finally:
            cur.close()
            conn.close()


    # Delete cipher before 11 hours.
    def delete_timer():
        conn = mysql.connector.connect(user='root', host='localhost', password='Passw0rd!', database='kerberos')
        cur = conn.cursor(buffered=True)
        try:

            while True:
                time.sleep(3600)
                now = datetime.now()
                now = float(now.timestamp() * 1000)
                pasteleven = now - 39600000
                print(now)
                print(pasteleven)
                deletequery = 'DELETE FROM cipher_table WHERE timestamp < %s'
                cur.execute(deletequery, (pasteleven,))
                conn.commit()
        finally:
            cur.close()
            conn.close()


    delete_thread = threading.Thread(target=delete_timer)
    delete_thread.start()


    app = Flask(__name__)

    @app.route('/tsharkmsg', methods=['POST'])
    def tsharkmsg():
        message = request.form.get('message', None)
        message = message.strip("'")

        message = json.loads(message)

        if message.get('layers').get('kerberos_msg_type'):
            if int(message['layers']['kerberos_msg_type'][0]) == 11:
                ip_src = message['layers']['ip_src'][0]
                ip_dst = message['layers']['ip_dst'][0]
                cipher = message['layers']['kerberos_cipher'][0]
                timestamp = message['timestamp']
                msg_type = 11
                t = threading.Thread(target=sqlinput_kereberos_msg, args=([ip_src, ip_dst, cipher, msg_type, timestamp]))
                t.start()
                return 'normal'

            elif int(message['layers']['kerberos_msg_type'][0]) == 13:
                ip_src = message['layers']['ip_src'][0]
                ip_dst = message['layers']['ip_dst'][0]
                cipher = message['layers']['kerberos_cipher'][0]
                timestamp = message['timestamp']
                msg_type = 13
                t = threading.Thread(target=sqlinput_kereberos_msg, args=([ip_src, ip_dst, cipher, msg_type, timestamp]))
                t.start()
                return 'normal'

            elif int(message['layers']['kerberos_msg_type'][0]) == 12:
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

        if message.get('layers').get('kerberos_error_code'):
            if int(message['layers']['kerberos_error_code'][0]) == 32:
                ip_src = message['layers']['ip_src'][0]
                ip_dst = message['layers']['ip_dst'][0]
                timestamp = message['timestamp']
                t = threading.Thread(target=sqlinput_kereberos_err, args=([ip_src, ip_dst, timestamp]))
                t.start()
                return 'normal'

        else:
            return 'normal'

except Exception as e:
    with open('parse_error.log', 'a') as f:
        print(e.args, file=f)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, threaded=True)

