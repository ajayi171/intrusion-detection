import streamlit as st
import pickle
import numpy as np
import pandas as pd 
from numpy import hstack
from numpy import vstack
from numpy import asarray
from PIL import Image

st.title("Intrusion Detection App")

att_model = pickle.load(open('att_model.pkl', 'rb'))
# intr_model = pickle.load(open('k_model.pkl', 'rb'))
models = pickle.load(open('sl_model.pkl', 'rb'))
meta_model=pickle.load(open('meta_model.pkl', 'rb'))

label_encoder2 = pickle.load(open('le2.pkl', 'rb'))
label_encoder4 = pickle.load(open('le4.pkl', 'rb'))

scaler1 = pickle.load(open('att_scal.pkl', 'rb'))

scaler2 = pickle.load(open('scal.pkl', 'rb'))

encoder = pickle.load(open('enc.pkl', 'rb'))
data_new = pd.read_csv('app_data.csv')

# sf = ['sbytes', 'dbytes', 'sttl', 'sload', 'dload', 
#      'smean', 'dmean', 'ct_srv_src', 'ct_srv_dst']

# sf2 =  ['sbytes', 'rate', 'sttl', 'sload', 'dload', 'tcprtt',
#     'smean', 'ct_state_ttl', 'ct_dst_src_ltm', 'ct_srv_dst']



# sf=['sbytes',
#  'smean',
#  'ct_srv_dst',
#  'ct_srv_src',
#  'dbytes',
#  'dload',
#  'sttl',
#  'dmean',
#  'sload']


# sf2=['ct_dst_src_ltm',
#  'sttl',
#  'ct_state_ttl',
#  'sbytes',
#  'ct_srv_dst',
#  'smean',
#  'sload',
#  'dload',
#  'rate']

# ['dur',
#  'sbytes',
#  'dbytes',
#  'sttl',
#  'sload',
#  'dload',
#  'smean',
#  'dmean',
#  'ct_srv_src',
#  'ct_srv_dst']

# ['sbytes',
#  'rate',
#  'sttl',
#  'sload',
#  'dload',
#  'tcprtt',
#  'smean',
#  'ct_state_ttl',
#  'ct_dst_src_ltm',
#  'ct_srv_dst']

X_train = ['dur', 'proto', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
       'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
       'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack',
       'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
       'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
       'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
       'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports']

col3 = ['sbytes', 'dbytes', 'rate',
       'sttl','sload', 'dload','synack','tcprtt', 
       'smean', 'dmean','ct_srv_src', 'ct_state_ttl',
       'ct_dst_src_ltm','ct_srv_dst']

selected_features = ['sbytes', 'smean', 'ct_srv_dst', 'dbytes', 'ct_srv_src', 'dmean',
       'sttl', 'sload', 'dload']
selected_features1 = ['sttl', 'ct_dst_src_ltm', 'sbytes', 'ct_srv_dst', 'ct_state_ttl',
       'smean', 'dload', 'synack', 'sload', 'rate']

def predict():

    c1,c2,c3 = st.columns(3)

    with c1:
        smean = st.number_input('Mean of the row packet size transmitted by the source')
        ct_srv_dst = st.number_input('No. of connections that contain the same service and destination address in 100 connections according to the last time.')
        ct_dst_src_ltm = st.number_input('No of connections of the same source and the destination address in 100 connections according to the last time.')
        sbytes = st.number_input('Number of data bytes transferred from source to destination in single connection')
        dbytes = st.number_input('Number of data bytes transferred from destination to source in single connection')
        
    with c2:
        sttl = st.number_input('Source to destination time to live value')
        ct_state_ttl = st.number_input('No. for each state according to specific range of values for source/destination time to live.')
        dload = st.number_input('Destination bits per second')
        dmean = st.number_input('Mean of the row packet size transmitted by the dst')
        synack = st.number_input('Syn-ack time')

    with c3:
        sload = st.number_input('Source bits per second')
        tcprtt = st.number_input('TCP connection setup round-trip time')
        ct_srv_src = st.number_input('No. of connections that contain the same service and source address in 100 connections according to the last time.')
        rate = st.number_input('rate')

    feat = np.array([sbytes,dbytes,rate,
       sttl,sload, dload,synack,tcprtt, 
       smean,dmean,ct_srv_src,ct_state_ttl,
       ct_dst_src_ltm,ct_srv_dst]).reshape(1,-1)

                

    feat1 = pd.DataFrame(feat,columns=col3)
        
    return feat1


def super_learner_predictions(X, models, meta_model):
    meta_X = list()
    for model in models:
        yhat = model.predict_proba(X)
        meta_X.append(yhat)
    meta_X = hstack(meta_X)
    # predict
    return meta_model.predict(meta_X)


def prepare(data):

    attack_df = data[selected_features]
    #attack_df['service'] = label_encoder2.transform(attack_df['service'])
    intr_df = data[selected_features1]

    attack_df = scaler1.transform(attack_df)
    intr_df = scaler2.transform(intr_df)

    return attack_df, intr_df


data = predict()
if st.button('Predict'):
    attack_df, intr_df = prepare(data)

    pred = super_learner_predictions(intr_df, models, meta_model)

    if pred[0] == 0:
        st.write("Normal Activity Permision Granted")
    else:
        pred1 = att_model.predict(attack_df)
        attack = label_encoder4.inverse_transform(pred1)
        # st.subheader(f"{attack[0]}")
        st.warning(f"{attack[0]} Intrusion Detected")
        st.image("dz1.gif")

        
