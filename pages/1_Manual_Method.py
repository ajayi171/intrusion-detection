import streamlit as st
import pickle
import numpy as np
import pandas as pd 
from numpy import hstack
from numpy import vstack
from numpy import asarray
from PIL import Image
import joblib

st.title("Intrusion Detection App")

att_model = joblib.load('att_model.pkl', 'rb')
# intr_model = joblib.load(open('k_model.pkl', 'rb'))
models = joblib.load('sl_model.pkl', 'rb')
meta_model=joblib.load('meta_model.pkl', 'rb')

label_encoder2 = joblib.load('le2.pkl', 'rb')
label_encoder4 = joblib.load('le4.pkl', 'rb')

scaler1 = joblib.load('att_scal.pkl', 'rb')

scaler2 = joblib.load('scal.pkl', 'rb')

encoder = joblib.load('enc.pkl', 'rb')
data_new = pd.read_csv('app_data.csv')


col3 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
        'dload','ct_srv_src','sbytes','dur', 'sload', 'tcprtt',
        'ct_srv_dst', 'dbytes', 'smean']


sf = ['dur', 'sbytes', 'dbytes', 'sttl', 'sload', 'dload', 
     'smean', 'dmean', 'ct_srv_src', 'ct_srv_dst']

sf2 =  ['sbytes', 'rate', 'sttl', 'sload', 'dload', 'tcprtt',
    'smean', 'ct_state_ttl', 'ct_dst_src_ltm', 'ct_srv_dst']


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
        dur = st.number_input('duration of connection')
        ct_state_ttl = st.number_input('No. for each state according to specific range of values for source/destination time to live.')
        dload = st.number_input('Destination bits per second')
        dmean = st.number_input('Mean of the row packet size transmitted by the dst')

    with c3:
        sload = st.number_input('Source bits per second')
        tcprtt = st.number_input('TCP connection setup round-trip time')
        ct_srv_src = st.number_input('No. of connections that contain the same service and source address in 100 connections according to the last time.')
        rate = st.number_input('rate')
        ct_dst_sport_ltm = st.number_input('No of connections of the same destination address and the source port in 100 connections according to the last time.')

    feat = np.array([ct_state_ttl,rate,sttl,dmean,ct_dst_src_ltm,
                      dload,ct_srv_src,sbytes,dur,sload,tcprtt,
                      ct_srv_dst,dbytes,smean]).reshape(1,-1)

                

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

    attack_df = data[sf]
    #attack_df['service'] = label_encoder2.transform(attack_df['service'])
    intr_df = data[sf2]

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

        

