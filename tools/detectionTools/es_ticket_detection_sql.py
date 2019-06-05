import time, threading, json
from datetime import datetime
from flask import Flask, request
import update_es
import mysql.connector
import atexit

try:
    conn = mysql.connector.connect(user='root', password='Passw0rd!', host='10.0.19.111', database='kerberos')
    cur = conn.cursor()

    # Search old cipher from SQL.
    def checkticket(ip_src, cipher, msg_type, timestamp):
        global cur

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
            curfet = cur.fetchall()

            if cur.rowcount != 0:
                print('TKT Expired at ' + str(timestamp))

            else:
                # n = 0
                # update_flag_event = True
                # while update_flag_event:
                #     update_flag_event = update_es.update_event(ip_src)
                #     time.sleep(1)
                #     n += 1
                #     if n >= 1000:
                #         break
                #
                # n = 0
                # update_flag_packet = True
                # while update_flag_packet:
                #     update_flag_packet = update_es.update_packet(cipher)
                #     time.sleep(1)
                #     n += 1
                #     if n >= 1000:
                #         break

                with open('./detected_ticket.log', mode='a') as f:
                    if msg_type == 12:
                        f.write('Golden ticket was used on ' + str(ip_src) + ' at ' + str(timestamp) + ' ' + str(cipher) + '\n')
                        print('Golden ticket was used on ' + str(ip_src) + ' at ' + str(timestamp))
                    if msg_type == 14:
                        print('Silver ticket was used on ' + str(ip_src) + ' at ' + str(timestamp))
                        f.write('Silver ticket was used on ' + str(ip_src) + ' at ' + str(timestamp) + ' ' + str(cipher) + '\n')


    # Insert msg_type 11 or 13 data into SQL.
    def sqlinput_kereberos_msg(ip_src, ip_dst, cipher, msg_type, timestamp):
        global cur, conn
        query = 'INSERT INTO cipher_table(ip_src, ip_dst, kerberos_cipher, msg_type, timestamp) VALUES (INET_ATON(%s), INET_ATON(%s), %s, %s, %s)'
        cur.execute(query, (ip_src, ip_dst, cipher, msg_type, timestamp))
        conn.commit()

    def sqlinput_kereberos_err(ip_src, ip_dst, timestamp):
        global cur, conn
        query = 'INSERT INTO cipher_table (ip_src, ip_dst, error_code, timestamp) VALUES (INET_ATON(%s), INET_ATON(%s), %s, %s)'
        cur.execute(query, (ip_src, ip_dst, 32, timestamp))
        conn.commit()


    # Delete cipher before 11 hours.
    def delete_timer():
        global cur, conn

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

    def all_done():
        print("Closing the DB connection.....")
        global cur, conn
        cur.close()
        conn.close()

except Exception as e:
    with open('parse_error.log', 'a') as f:
        print(e.args, file=f)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, threaded=True)
    atexit.register(all_done)


