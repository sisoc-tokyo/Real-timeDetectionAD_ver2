import os, pickle, json
import pandas as pd
from flask import Flask, request

df_log='df_logs.pickle'

print('init called')
if os.path.exists(df_log)==True:
    with open(df_log, mode='rb') as f:
        df=pickle.load(f)
else:
    df = pd.DataFrame()

app = Flask(__name__)

@app.route('/cipher', methods=['POST'])
def cipher():
    global df
    message = request.form.get('message', None)
    message = message.strip("'")
    try:
        message = json.loads(message)
    except:
        with open('parse_error.log', 'a') as f:
            print(message, file=f)
        return 'parse_error'

    if int(message['layers']['kerberos_msg_type'][0]) == 11:
        df_timestamp = pd.DataFrame([message['timestamp']], columns=['timestamp'])
        df_data = pd.DataFrame.from_dict(message['layers'])
        df_line = pd.concat([df_timestamp, df_data], axis=1)
        df = pd.concat([df, df_line])

    elif int(message['layers']['kerberos_msg_type'][0]) == 14:
        cipher = message['layers']['kerberos_cipher'][0]
        if 'kerberos_cipher' in df.columns:
            result = df[df.kerberos_cipher.str.contains(cipher)]
            if len(result) == 0:
               print('attack')
               return 'attack'

    print('normal')
    return 'normal'

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0')
    finally:
        print('finally called')
        with open(df_log, mode='wb') as handle:
            pickle.dump(df, handle, protocol=pickle.HIGHEST_PROTOCOL)