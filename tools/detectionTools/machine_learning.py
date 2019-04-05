import pandas as pd
import numpy as np
from flask import jsonify
from signature_detection import SignatureDetector

class ML:
    RESULT_WARN = "warning: command on blackList is used but is used daily operation"
    RESULT_UNKNOW_ACCOUNT = "attack: unknown account is used"

    @staticmethod
    def preds(eventid, accountname, processname, objectname, base_dummies_4674, clf_4674, base_dummies_4688, clf_4688):
        # loading
        response = ""
        new_data = []
        if accountname != None:
            accountname = accountname.lower()
            accountname = 'account_' + str(accountname)
            new_data.append(accountname)
        processname = 'process_' + str(processname)
        new_data.append(processname)
        objectname = 'objectname_' + str(objectname)
        new_data.append(objectname)

        base_df_4674 = pd.DataFrame(columns=base_dummies_4674.columns[1:-1])
        base_df_4674.loc[0] = 0
        base_df_4688 = pd.DataFrame(columns=base_dummies_4688.columns[1:-1])
        base_df_4688.loc[0] = 0

        if accountname not in base_df_4674.columns and accountname not in base_df_4688.columns:
            response = ML.RESULT_UNKNOW_ACCOUNT
            print(ML.RESULT_UNKNOW_ACCOUNT)
            return response
        if processname not in base_df_4674.columns and processname not in base_df_4688.columns:
            response = SignatureDetector.RESULT_CMD
            print(SignatureDetector.RESULT_CMD)
            return response

        for colname in new_data:
            if colname in base_df_4674.columns:
                base_df_4674[colname][0] = 1
            if colname in base_df_4688.columns:
                base_df_4688[colname][0] = 1

        if eventid == '4674':
            base_df_4674['eventID'][0] = '4674'
            base_df_4674 = base_df_4674.astype(np.int32)
            pred_data = base_df_4674.values
            result = clf_4674.predict(pred_data)
            if result == 1:
                print('Signature B_command matched but it seems used in daily operations')
                response = ML.RESULT_WARN
            elif result == -1:
                print('Signature B_command matched and it seems unusual behavior')
                response = SignatureDetector.RESULT_CMD

        if eventid == '4688':
            base_df_4688['eventID'][0] = '4688'
            base_df_4688 = base_df_4688.astype(np.int32)
            pred_data = base_df_4688.values
            result = clf_4688.predict(pred_data)
            if result == 1:
                print('Signature B_command matched but it seems used in daily operations')
                response = ML.RESULT_WARN
            elif result == -1:
                print('Signature B_command matched and it seems unusual behavior')
                response = SignatureDetector.RESULT_CMD

        # save
        # with open('request.log', mode='a') as f:
        #     f.write(str(response.status_code) + str(prediction) + ',' + str(reqstr) + '\n')

        return response