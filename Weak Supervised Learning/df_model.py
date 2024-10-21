from deepforest import CascadeForestClassifier
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import data_processing as d
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, roc_curve, classification_report
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
def load_data ():
    userid = d.load_user_id()
    account_pair = d.load_account_pair(userid, w=0.1)
    p, r, f1 = d.gc_pref_result(userid, account_pair)
    X,y = d.account_pair_fetures(account_pair, features='both')
    return X,y

def mlp (X_train,y_train, X_test, y_test):
    mlp = MLPClassifier(solver='adam', activation='relu')
    mlp.fit(X_train, y_train)
    y_pred1 = mlp.predict(X_train)
    print(classification_report(y_train, y_pred1))

def rf (X_train,y_train, X_test, y_test):
    parameters = {'bootstrap': True,
                  'min_samples_leaf': 5,
                  'n_estimators': 100,
                  'min_samples_split': 50,
                  'max_features': 'sqrt',
                  'max_depth': 8,
                  'max_leaf_nodes': None}

    RF_model = RandomForestClassifier(**parameters)
    RF_model.fit(X_train, y_train)
    y_pred1 = RF_model.predict(X_train)
    print(classification_report(y_train, y_pred1))

def lr (X_train,y_train, X_test, y_test):
    clf = LogisticRegression().fit(X_train, y_train)
    y_pred1 = clf.predict(X_train)
    print(classification_report(y_pred1, y_train))

if __name__ == '__main__':
    X,y =load_data()
    X = X.to_numpy()
    y = y.to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(X, y,test_size=0.2,random_state=43)

    model = CascadeForestClassifier(random_state=1)
    n_estimators = 4
    estimators = [RandomForestClassifier(random_state=i) for i in range(n_estimators)]
    model.set_estimator(estimators)  # set custom base estimators
    model.fit(X_train, y_train)
    y_pred1 = model.predict(X_train)

    print(classification_report(y_train,y_pred1))
    mlp(X_train,y_train,1,1)
    rf(X_train,y_train,1,1)
    lr(X_train,y_train,1,1)


