import streamlit as st
from PIL import Image
import os

os.system('sudo apt install -y tshark')
st.set_page_config(
    page_title="Hello",
    page_icon="👋",
)
img = Image.open('nit.png')
st.write("# AN INTELLIGENT INTRUSION DETECTION SYSTEM FOR MITIGATING NETWORK ATTACKS! 👋")

st.sidebar.success("Select a testing method above")

st.markdown(
    """
    This is an intelligent system leverages the power of machine learning to identify network intrusion.
    You have the option of  selecting a testing method from the sidebar.
    
"""
)
st.image(img, width=700)
