import os
import csv
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from IPython.display import display
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.decomposition import PCA
from sklearn.externals import joblib

df = pd.read_csv('eventlog.csv')
print(df)


def learning(eventid, df, nu, gamma):
    df = df[df.eventID == eventid]
    data_dummies = pd.get_dummies(df.iloc[:, 1:])
    data_dummies = pd.concat([df.iloc[:, 0], data_dummies], axis=1)
    data_dummies.to_csv('data_dummies.csv')
    print(eventid)

    if 'train' not in df.target.values:
        print('No train value in the target column')
        print('')
        return

    if 'test' not in df.target.values:
        print('No test value in the target column')
        print('')
        return

    if 'outlier' not in df.target.values:
        print('No outlier value in the target column')
        print('')
        return

    data_normal = data_dummies[data_dummies.target_train == 1]
    data_test = data_dummies[data_dummies.target_test == 1]
    data_outliers = data_dummies[data_dummies.target_outlier == 1]
    X_train = data_normal.ix[:, 1:-3].values
    X_test = data_test.ix[:, 1:-3].values
    X_outliers = data_outliers.ix[:, 1:-3].values

    X_all = data_dummies.ix[:, 1:-3].values
    X_index = data_dummies.ix[:, -3:].values

    clf = svm.OneClassSVM(nu=nu, kernel="rbf", gamma=gamma)
    clf.fit(X_train)

    # n_correct_test is True Negative
    # n_error_test is False Positive
    # n_correct_outliers is True Positive
    # n_error_outliers is False Negative

    X_pred_train = clf.predict(X_train)
    X_pred_test = clf.predict(X_test)
    X_pred_outliers = clf.predict(X_outliers)
    n_correct_train = X_pred_train[X_pred_train == 1].size
    n_error_train = X_pred_train[X_pred_train == -1].size
    n_correct_test = X_pred_test[X_pred_test == 1].size
    n_error_test = X_pred_test[X_pred_test == -1].size
    n_correct_outliers = X_pred_outliers[X_pred_outliers == -1].size
    n_error_outliers = X_pred_outliers[X_pred_outliers == 1].size
    recall = n_correct_outliers / (n_correct_outliers + n_error_outliers)
    precision = n_correct_outliers / (n_correct_outliers + n_error_test)
    specificity = n_correct_test / (n_correct_test + n_error_test)
    accuracy = (n_correct_test + n_correct_outliers) / (
                n_correct_test + n_error_test + n_correct_outliers + n_error_outliers)
    f_value = (2 * n_correct_outliers) / (2 * n_correct_outliers + n_error_test + n_error_outliers)

    print('svm.OneClassSVM(nu=' + str(nu) + ', kernel="rbf", gamma=' + str(gamma) + ')')
    print('Training Correct: ' + str(n_correct_train))
    print('Training Error: ' + str(n_error_train))
    print('True Negative: ' + str(n_correct_test))
    print('False Positive: ' + str(n_error_test))
    print('True Positive: ' + str(n_correct_outliers))
    print('False Negative: ' + str(n_error_outliers))
    print('Recall: ' + str(recall))
    print('Precision: ' + str(precision))
    print('Specificity: ' + str(specificity))
    print('Accuracy: ' + str(accuracy))
    print('F_Value: ' + str(f_value))
    print('')

    X_train_result = np.concatenate((df[df['target'] == 'train'], X_pred_train[np.newaxis, :].T), axis=1)
    X_test_result = np.concatenate((df[df['target'] == 'test'], X_pred_test[np.newaxis, :].T), axis=1)
    X_outliers_result = np.concatenate((df[df['target'] == 'outlier'], X_pred_outliers[np.newaxis, :].T), axis=1)

    with open('X_train_result' + str(eventid) + '.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(X_train_result)

    with open('X_test_result' + str(eventid) + '.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(X_test_result)

    with open('X_outliers_result' + str(eventid) + '.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(X_outliers_result)

    joblib.dump(clf, 'ocsvm_gt.pkl')

nu_list = [0.1, 0.01, 0.001]
gamma_list = [0.1, 0.01, 0.001]

for nu in nu_list:
    for gamma in gamma_list:
        #learning(4672, df, nu, gamma)
        #learning(4673, df, nu, gamma)
        learning(4674, df, nu, gamma)
        #learning(4688, df, nu, gamma)
        #learning(4768, df, nu, gamma)
        #learning(4769, df, nu, gamma)
        #learning(5140, df, nu, gamma)