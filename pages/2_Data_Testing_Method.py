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


col3 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
        'dload','ct_srv_src','sbytes', 'sload', 'tcprtt',
        'ct_srv_dst', 'dbytes', 'smean','synack']

col4 = ['ct_state_ttl','rate','sttl','dmean','ct_dst_src_ltm',
        'dload','ct_srv_src','sbytes', 'sload', 'tcprtt',
        'ct_srv_dst', 'dbytes', 'smean','attack_cat']

# col3 = ['sbytes', 'dbytes', 'rate',
#        'sttl','sload', 'dload','synack','tcprtt', 
#        'smean', 'dmean','ct_srv_src', 'ct_state_ttl',
#        'ct_dst_src_ltm','ct_srv_dst']

selected_features = ['sbytes', 'smean', 'ct_srv_dst', 'dbytes', 'ct_srv_src', 'dmean',
       'sttl', 'sload', 'dload']
selected_features1 = ['sttl', 'ct_dst_src_ltm', 'sbytes', 'ct_srv_dst', 'ct_state_ttl',
       'smean', 'dload', 'synack', 'sload', 'rate']

# sf = [ 'sbytes', 'dbytes', 'sttl', 'sload', 'dload', 
#      'smean', 'dmean', 'ct_srv_src', 'ct_srv_dst']

# sf2 =  ['sbytes', 'rate', 'sttl', 'sload', 'dload', 'tcprtt',
#     'smean', 'ct_state_ttl', 'ct_dst_src_ltm', 'ct_srv_dst']

tags = ['No. for each state according to specific range of values for source/destination time to live',
'rate','Source to destination time to live value', 'Mean of the row packet size transmitted by the dst',
'No of connections of the same source and the destination address in 100 connections according to the last time.',
'Destination bits per second',
'No. of connections that contain the same service and source address in 100 connections according to the last time.',
'Number of data bytes transferred from source to destination in single connection',
'Source bits per second','TCP connection setup round-trip time',
'No. of connections that contain the same service and destination address in 100 connections according to the last time.',
'Number of data bytes transferred from destination to source in single connection',
'Mean of the row packet size transmitted by the source',
'Syn-ack time'
]

data2 = data_new[col3]
data3 = data_new[col4]
st.dataframe(data3)


row_num = st.number_input('Select Row, You would like to Predict', min_value=0, max_value=data2.shape[0]-1, step=1)
new_d = data2.iloc[row_num]
new_ddd = new_d.to_list()
new_d = pd.DataFrame(new_d)
new_d['Full Name'] = tags
st.dataframe(new_d)
feat2 = np.array(new_ddd).reshape(1,-1)
feat2 = pd.DataFrame(feat2,columns=col3)


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


if st.button('Prediction'):
    attack_df, intr_df = prepare(feat2)

    pred = super_learner_predictions(intr_df, models, meta_model)

    if pred[0] == 0:
        st.write("Normal Activity Permision Granted")
    else:
        pred1 = att_model.predict(attack_df)
        attack = label_encoder4.inverse_transform(pred1)
        # st.subheader(f"{attack[0]}")
        st.warning(f"{attack[0]} Intrusion Detected")
        st.image("dz1.gif")


        
