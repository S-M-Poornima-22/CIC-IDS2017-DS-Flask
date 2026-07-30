from glob import glob

import joblib
from PIL import Image
import pandas as pd

from flask import Flask, request, render_template, redirect, url_for
import os
from matplotlib.colors import LogNorm

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model
matplotlib.use('Agg')



app = Flask(__name__)
app.secret_key = "MySecret"
ctx = app.app_context()
ctx.push()

with ctx:
    pass
user_id = ""
emailid = ""

message = ""
msgType = ""
uploaded_file_name = ""


def initialize():
    global message, msgType
    message = ""
    msgType = ""


@app.route("/")
def index():
    global user_id, emailid
    return render_template("Login.html")


@app.route("/processLogin", methods=["POST"])
def processLogin():
    global user_id, emailid
    emailid = request.form["emailid"]
    password = request.form["password"]
    sdf = pd.read_csv("static/System.csv")
    print(sdf, "XXXXXXXXXXXXXXXXXXXXXXXXXXXX")
    for k, v in sdf.iterrows():
        if v['emailid'] == emailid and str(v['password']) == password:
            return render_template("Dashboard.html")
    return render_template("Login.html", processResult="Invalid UserID and Password")


@app.route("/ChangePassword")
def changePassword():
    global user_id, emailid
    return render_template("ChangePassword.html")



@app.route("/ProcessChangePassword", methods=["POST"])
def processChangePassword():
    global user_id, emailid
    oldPassword = request.form.form["oldPassword"]
    newPassword = request.form.form["newPassword"]

    return render_template("ChangePassword.html", msg="Password Changed Successfully")


@app.route("/Dashboard")
def Dashboard():
    global user_id, emailid
    return render_template("Dashboard.html")


@app.route("/Information")
def Information():
    global message, msgType
    return render_template("Information.html", msgType=msgType, message=message)




def get_datasets():
    file_list = os.listdir("static/Dataset")
    print(file_list)
    return file_list


df : pd.DataFrame = None
data_dir = 'static/CIC-IDS2017-Dataset'
original_shape = None
missing_data = None
cleaned_shape = None
duplicated_rows = None



def load_dataset():
    global df, original_shape, missing_data, duplicated_rows, cleaned_shape
    if df is None:
        nrows = 1000
        df1 = pd.read_csv(f"{data_dir}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", nrows=nrows)
        df2 = pd.read_csv(f"{data_dir}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", nrows=nrows)
        df3 = pd.read_csv(f"{data_dir}/Friday-WorkingHours-Morning.pcap_ISCX.csv", nrows=nrows)
        df4 = pd.read_csv(f"{data_dir}/Monday-WorkingHours.pcap_ISCX.csv", nrows=nrows)
        df5 = pd.read_csv(f"{data_dir}/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", nrows=nrows)
        df6 = pd.read_csv(f"{data_dir}/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", nrows=nrows)
        df7 = pd.read_csv(f"{data_dir}/Tuesday-WorkingHours.pcap_ISCX.csv", nrows=nrows)
        df8 = pd.read_csv(f"{data_dir}/Wednesday-workingHours.pcap_ISCX.csv", nrows=nrows)
        df = pd.concat([df1,df2, df3, df4,df5,df6,df7,df8])
        df.columns = df.columns.str.strip()
        original_shape = df.shape
        missing_data = df.isna().sum()
        duplicated_rows = df.duplicated().sum()
        df.drop_duplicates(inplace=True)
        cleaned_shape = df.shape
        pass


load_dataset()



@app.route("/DatasetInfo")
def DatasetInfo():
    return render_template("DatasetInfo.html", displayResult=False)


@app.route("/ProcessDatasetInfo", methods=['POST'])
def process_DatasetInfo():
    global df
    return render_template("DatasetInfo.html", displayResult=True, records = df.head(1000))

@app.route("/Statistics")
def Statistics():
    return render_template("Statistics.html", displayResult=False)


@app.route("/ProcessStatistics", methods=['POST'])
def process_Statistics():
    numeric_df = df.select_dtypes(include=['number'])
    records = numeric_df.describe()
    return render_template("Statistics.html", displayResult=True, records=records)

@app.route("/Metadata")
def Metadata():
    return render_template("Metadata.html", displayResult=False)


@app.route("/ProcessMetadata", methods=['POST'])
def process_Metadata():
    records = df.dtypes
    memory_usage = df.memory_usage()
    return render_template("Metadata.html", displayResult=True, records=records, memory_usage=memory_usage)

@app.route("/DataPreprocessing")
def DataPreprocessing():
    return render_template("DataPreprocessing.html", displayResult=False)


@app.route("/ProcessDataPreprocessing", methods=['POST'])
def process_DataPreprocessing():
    global original_shape, missing_data, duplicated_rows, cleaned_shape
    return render_template("DataPreprocessing.html", displayResult=True, original_shape=original_shape, missing_data=missing_data, duplicated_rows=duplicated_rows, cleaned_shape=cleaned_shape)


@app.route("/ClassCount")
def ClassCount():
    return render_template("ClassCount.html", displayResult=False)


@app.route("/ProcessClassCount", methods=['POST'])
def process_ClassCount():
    
    global df
    plt.figure(figsize=(10,10))
    sns.countplot(data=df, x="Label", hue="Label", palette="bright")
    plt.title("Label Count")
    plt.xlabel("Label")
    plt.ylabel("Count")
    plt.savefig("static/Output/ClassCount.png")

    return render_template("ClassCount.html", displayResult=True)    

'''
No Attack
80, 10440135,        5,        0,       30,        0,  5,       30,        0,        0,       -1,        4,    20
80, 10453138,        4,        0,       24,        0,  4,       24,        0,        0,       -1,        3,   20
              
Attack

80,     1632,        3,        6,       26,    11607,  3,       26,        6,    11607,      229,        2,   20
80,    13724,        3,        6,       26,    11601,   3,       26,        6,    11601,      229,        2,  20



'''

@app.route("/Prediction")
def Prediction():
    return render_template("Prediction.html", displayResult=False)

def get_prediction(DestinationPort, FlowDuration, TotalFwdPackets, TotalBackwardPackets, TotalLengthofFwdPackets,
                   TotalLengthofBwdPackets, SubflowFwdPackets, SubflowFwdBytes, SubflowBwdPackets, SubflowBwdBytes, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward):

    auto_encoder_model = load_model("static/Auto-Encoder-Decoder.keras")
    ada = joblib.load("static/Ada-Boost-Classsifier.joblib")
    input_data = [[DestinationPort, FlowDuration, TotalFwdPackets, TotalBackwardPackets, TotalLengthofFwdPackets,
                   TotalLengthofBwdPackets, SubflowFwdPackets, SubflowFwdBytes, SubflowBwdPackets, SubflowBwdBytes, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward ]]
    sc = joblib.load("static/Standard-Scaler.joblib")
    input_data_scaled = sc.transform(input_data)
    y_pred_prob = ada.predict(input_data_scaled)
    print(y_pred_prob[0])
    prediction_message = "No Intrusion Detection Found"
    if y_pred_prob[0] > 0.5:
        prediction_message = "Intrusion Detection Found"
    return prediction_message
@app.route("/ProcessPrediction", methods=['POST'])
def process_Prediction():
    DestinationPort = request.form["DestinationPort"]
    FlowDuration = request.form["FlowDuration"]
    TotalFwdPackets = request.form["TotalFwdPackets"]
    TotalBackwardPackets = request.form["TotalBackwardPackets"]
    TotalLengthofFwdPackets = request.form["TotalLengthofFwdPackets"]
    TotalLengthofBwdPackets = request.form["TotalLengthofBwdPackets"]
    SubflowFwdPackets = request.form["SubflowFwdPackets"]
    SubflowFwdBytes = request.form["SubflowFwdBytes"]
    SubflowBwdPackets = request.form["SubflowBwdPackets"]
    SubflowBwdBytes = request.form["SubflowBwdBytes"]
    Init_Win_bytes_backward = request.form["Init_Win_bytes_backward"]
    act_data_pkt_fwd = request.form["act_data_pkt_fwd"]
    min_seg_size_forward = request.form["min_seg_size_forward"]
    prediction_message = get_prediction(DestinationPort, FlowDuration, TotalFwdPackets, TotalBackwardPackets, TotalLengthofFwdPackets,
                   TotalLengthofBwdPackets, SubflowFwdPackets, SubflowFwdBytes, SubflowBwdPackets, SubflowBwdBytes, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward)
    return render_template("Prediction.html", displayResult=True, prediction_message=prediction_message, DestinationPort=DestinationPort, FlowDuration=FlowDuration, TotalFwdPackets=TotalFwdPackets, TotalBackwardPackets=TotalBackwardPackets, TotalLengthofFwdPackets=TotalLengthofFwdPackets, TotalLengthofBwdPackets=TotalLengthofBwdPackets, SubflowFwdPackets=SubflowFwdPackets, SubflowFwdBytes=SubflowFwdBytes, SubflowBwdPackets=SubflowBwdPackets, SubflowBwdBytes=SubflowBwdBytes, Init_Win_bytes_backward=Init_Win_bytes_backward, act_data_pkt_fwd=act_data_pkt_fwd, min_seg_size_forward=min_seg_size_forward)

@app.route("/ModelPerformance")
def ModelPerformance():
    return render_template("ModelPerformance.html", displayResult=False)


@app.route("/ProcessModelPerformance", methods=['POST'])
def process_ModelPerformance():

    return render_template("ModelPerformance.html", displayResult=True)    



if __name__ == "__main__":

    app.run()
# test change