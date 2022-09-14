# to run, truffle compile and migrate after opening Ganache UI
# to run in development: FLASK_APP=main.py FLASK_ENV=development flask run
from ssl import SSLContext
from tkinter.messagebox import IGNORE
from flask import Flask, request, render_template, redirect
from formmodel import AuditRegForm, AuditActions
from formmodel import PatientRegForm, PatientActions
from formmodel import DoctorRegForm, DoctorActions
from formmodel import LogForm
from flask_bootstrap import Bootstrap
import hashlib
import pandas as pd
import pyaes
from datetime import datetime
from dateutil import parser
import clipboard
from web3.contract import Contract
from web3._utils.events import get_event_data
from eth_utils import event_abi_to_log_topic
from web3 import Web3
import json
import os

# connect to ganache
ganache_url = "HTTP://0.0.0.0:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))
print("Web3 is connected = " + str(web3.isConnected()))

# connect to remix
f = open('abi.json',)
abi = json.load(f)
f = open('bytecode.json',)
bytecode = json.load(f)['object']
contract = web3.eth.contract(abi=abi, bytecode=bytecode)

app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=b'\xd6\x04\xbdj\xfe\xed$c\x1e@\xad\x0f\x13,@G')
Bootstrap(app)

file = open('data/AESkey.txt', 'rb') # fernet key generated beforehand for once
enc_key  = file.read()
file.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')
global count_acc

@app.route('/patientsignup', methods=['GET', 'POST'])
def patient_registration():
    form = PatientRegForm(request.form)
    global count_acc
    if request.method == 'POST' and form.validate_on_submit():
            try:
                account_num= web3.eth.accounts[int(form.account_number.data)]
            except:
                print("Account number failed")

            try:
                web3.eth.defaultAccount = account_num
            except:
                print("Account number failed")
            
            tx_hash = contract.constructor(str(form.name_first.data),str(form.name_last.data),str(form.insurance.data),"bdate", str(form.email.data),str(form.phone.data),str(form.zip_code),str(form.city.data),"ekey").transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)

            username = form.name_first.data + " " + form.name_last.data
            address = account_num

            fname = hashlib.sha224(b"signin_data").hexdigest()
            f = open("data/"+fname+".csv", "a")
            salt = os.urandom(16)
            #pass_hash = bcrypt.hashpw(str(form.pasword.data), bcrypt.gensalt())
            pass_hash = hashlib.sha512(salt+ str(form.password.data).encode('utf-8')).hexdigest()           
            encrypted_data = "patient" + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.name_first.data)) + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.name_last.data)) + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.email.data))  + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.phone.data))  + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.city.data))  + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.zip_code.data,))  + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.insurance.data))  + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(salt)) + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(pass_hash)) + ", " +\
                    str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(address)) + "\n"
            f.write(encrypted_data)
            f.close()
            print(bytes(str(address),encoding='utf-8'))
            pk = "Will be sent to your email"
            result = "Please note your Blockchain address and contract address for future Login!"
            return render_template('result.html', result=result, username = username, address = address, pk=pk, tx_hash = tx_hash.hex(), tx_receipt = tx_receipt)
    return render_template('patientsignup.html', form=form)

@app.route('/auditorsignup', methods=['GET', 'POST'])
def audit_registration():
    form = AuditRegForm(request.form)
    global account_num
    account_num = 0
    if request.method == 'POST' and form.validate_on_submit():
        try:
            account_num= web3.eth.accounts[int(form.account_number.data)]
        except:
             print("Account number failed")
        fname = hashlib.sha224(b"signin_data").hexdigest()
        f = open("data/"+fname+".csv", "a")
        salt = os.urandom(16)
        pass_hash = hashlib.sha512(salt+ str(form.password.data).encode('utf-8')).hexdigest()
        encrypted_data = "audit" + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.name_first.data)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.name_last.data)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.email.data,))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.employee_id.data))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt("n/a"))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt("00008"))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt("0000000000"))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(salt)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(pass_hash)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(account_num)) + "\n"
        f.write(encrypted_data)
        f.close()
        username = form.name_first.data + " " + form.name_last.data
        address = account_num
        pk = "Will be sent to your email"
        result = "Please note your Blockchain address and contract address for future Login!"
        return render_template('result.html', result=result, username = username, address = address, pk=pk, tx_hash =0, tx_receipt=0)
    return render_template('auditorsignup.html', form=form)

@app.route('/doctorsignup', methods=['GET', 'POST'])
def doctor_registration():
    form = DoctorRegForm(request.form)
    global account_num
    account_num = 0
    if request.method == 'POST' and form.validate_on_submit():
        try:
            account_num= web3.eth.accounts[int(form.account_number.data)]
        except:
             print("Account number failed")
        fname = hashlib.sha224(b"signin_data").hexdigest()
        f = open("data/"+fname+".csv", "a")
        salt = os.urandom(16)
        pass_hash = hashlib.sha512(salt+ str(form.password.data).encode('utf-8')).hexdigest()       
        encrypted_data = "doctor" + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.name_first.data)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.name_last.data)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.email.data,))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(form.employee_id.data))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt("n/a"))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt("00008"))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt("0000000000"))  + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(salt)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(pass_hash)) + ", " +\
                str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(account_num)) + "\n"
        f.write(encrypted_data)
        f.close()
        username = form.name_first.data + " " + form.name_last.data
        address = account_num
        pk = "Will be sent to your email"
        result = "Please note your Blockchain address and contract address for future Login!"
        return render_template('result.html', result=result, username = username, address = address, pk=pk, tx_hash =0, tx_receipt=0)
    return render_template('doctorsignup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    fname = hashlib.sha224(b"signin_data").hexdigest()
    form = LogForm(request.form)
    address = form.user_name.data  
    
    if request.method == 'POST' and form.validate_on_submit():
        df=pd.read_csv("data/"+fname+".csv") 
        token = df['address'].apply(lambda x: bytes(str(x),'utf-8'))
        token2 = token.apply(lambda x: pyaes.AESModeOfOperationCTR(enc_key).decrypt(x))
        #decrypted_df = token2.apply(lambda x: x.decode('utf-8'))
        idx = token2.index[token2 == address]
        row = df.loc[idx]
        salt = pyaes.AESModeOfOperationCTR(enc_key).decrypt(row.salt[2:-1])
        hashed_pass = hashlib.sha512(salt+ str(form.password.data).encode('utf-8')).hexdigest()
        hashed_encrypt_pass = str(pyaes.AESModeOfOperationCTR(enc_key).encrypt(hashed_pass))
        if(row.password.to_string(index = False) == hashed_encrypt_pass):
            error = 'Invalid Credentials. Please try again.'
        else:
            if str(form.contract_address.data) != "0" and str(form.contract_address.data) != "1":
                return redirect('patient?'+"address=" + str(form.user_name.data) + "&contract=" + str(form.contract_address.data) )
            elif str(form.contract_address.data) == "1":
                return redirect('audit?'+"address=" + form.user_name.data + "&contract=1")
            else:
                return redirect('doctor?'+ "address=" + form.user_name.data + "&contract=0")
    return render_template('login.html', form=form, error=error)

@app.route('/patient', methods=['GET', 'POST'])
def patientdash():
    form = PatientActions(request.form)
    account_address  = request.args.get("address")
    contract_address = request.args.get("contract")
    isCard = False
    if request.method == 'POST':
        if request.form.get('action1') == 'VALUE1':
            isCard  = True
            appointment_date = form.start_visit.data
            result = "Patient initiated visit."

            contract = web3.eth.contract(address = contract_address, abi = abi)
            web3.eth.defaultAccount = account_address
            date_obj = parser.parse(form.start_visit.data)
            date_epoch = date_obj.timestamp()
            tx_hash  = contract.functions.start_visit(int(date_epoch)).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_start_visit.getLogs()
            qr_code = "https://api.qrserver.com/v1/create-qr-code/?data="+event_logs[0]['args']['record_unique_id']+"&size=150x150"

            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            fname = hashlib.sha224(b"uniqueid_data").hexdigest()
            f = open("data/"+fname+".csv", "a")
            data = str(contract_address) + ","+ str(event_logs[0]['args']['record_unique_id'])+"\n"
            f.write(data)
            f.close()
            return render_template("patient.html", form=form, isStart = True, isCard  = isCard, username=account_address,contract_address=contract_address, date = appointment_date, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs, qr_code=qr_code)
        
        elif  request.form.get('action2') == 'VALUE2':
            isCard  = True
            dr_id = form.add_doctors.data
            result = "Patient added a doctor to access their medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)

            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.addDoctors(dr_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_add_doctor.getLogs()

            print("--------------------changes-------------")
            print(event_logs[0]['args']['return_msg'])
            print("--------------------end changes-------------")

            return render_template("patient.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs)
       
        elif  request.form.get('action3') == 'VALUE3':
            isCard  = True
            dr_id = form.remove_doctors.data
            result = "Patient revoked access to a doctor their medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)
            
            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.removeDoctors(dr_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_remove_doctor.getLogs()

            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            return render_template("patient.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs)
        
        elif  request.form.get('action4') == 'VALUE4':
            isCard  = True
            audit_id = form.add_audits.data
            result = "Patient added an audit to view/change their medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)

            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.addAudit(audit_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_add_audit.getLogs()

            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            return render_template("patient.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs)

        elif  request.form.get('action5') == 'VALUE5':
            isCard  = True
            audit_id = form.remove_audits.data
            result = "Patient revoked access for an audit to view/change their medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)

            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.removeAudit(audit_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_remove_audit.getLogs()

            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            return render_template("patient.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs)


        elif  request.form.get('action6') == 'VALUE6':
            isCard  = True
            unique_id = form.print_record.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Patient printed their medical records."
 
            contract = web3.eth.contract(address = contract_address, abi = abi)
            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.print_record(unique_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_patient_print.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            record_details  = contract.functions.get_record_details(unique_id).call()
            print(record_details)

            return render_template("patient.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs, record_details = record_details)

        elif  request.form.get('action7') == 'VALUE7':
            isCard  = True
            unique_id = form.delete_record.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Patient deleted their medical record."

            contract = web3.eth.contract(address = contract_address, abi = abi)

            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.delete_record(unique_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_patient_delete.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            return render_template("patient.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs)
        else:
            pass # unknown
    
    return render_template('patient.html', form=form, isCard  = isCard, username=account_address,contract_address=contract_address )

@app.route('/audit', methods=['GET', 'POST'])
def auditdash():
    account_address  = request.args.get("address")
    contract_address = request.args.get("contract")
    form = AuditActions(request.form)
    if request.method == 'POST':
        if request.form.get('action10') == 'VALUE10':
            contract_address  = form.contract_address.data
            return redirect('audit?'+"address=" + str(account_address) + "&contract=" + str(form.contract_address.data) )
        if request.form.get('action1') == 'VALUE1':
            print("-------------contract address  = " +contract_address)
            isCard  = True
            unique_id = form.print_record.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Audit printed patient medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)

            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.doctor_print_record(unique_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_doctor_print.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            record_details  = contract.functions.get_record_details(unique_id).call()
            print(record_details)

            return render_template("auditor.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs, record_details = record_details)


        elif  request.form.get('action3') == 'VALUE3':
            isCard  = True
            unique_id = form.query.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Audit queried one of the patient medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)
            web3.eth.defaultAccount = account_address

            topic2abi = {event_abi_to_log_topic(_): _
                 for _ in contract.abi if _['type'] == 'event'}

            logs = web3.eth.getLogs(dict(
                    address=contract_address,
                    fromBlock=0,
                    toBlock=None
                    ))

            df1 = pd.DataFrame(columns = ['record_msg', 'record_status', 'record_time','audit_address','doctor_address'])
            l = []
            for entry in logs:
                topic0 = entry['topics'][0]
                if topic0 in topic2abi:
                    record_details = get_event_data(web3.codec, topic2abi[topic0], entry)
                    l.append(record_details.args)
            
            tx_hash  = contract.functions.doctor_query_record(unique_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_doctor_query.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            
            for d in l:
                temp = []
                if('record_msg' in d):
                    temp.insert(0,d.record_msg)
                else:
                    temp.insert(0,d.return_msg)
                if('record_status' in d):
                    temp.append(d.record_status)
                else:
                    temp.append(-1)
                temp.append(datetime.utcfromtimestamp(d.record_time).strftime('%Y-%m-%d %H:%M:%S'))

                if('audit_address' in d):
                    temp.append(d.audit_address)
                else:
                    temp.append(-1)
                if('doctor_address' in d):
                    temp.append(d.doctor_address)
                else:
                    temp.append(-1)
                a_series = pd.Series(temp, index = df1.columns)
                df1 = df1.append(a_series, ignore_index=True)

            return render_template("auditquery.html", form=form, username=account_address,contract_address=contract_address,isData = True, data = df1)

        elif  request.form.get('action30') == 'VALUE30':
            fname = hashlib.sha224(b"uniqueid_data").hexdigest()
            df = pd.read_csv('data/'+fname+'.csv')
            print(df)
            filtered_df = df[df['contract_address']==contract_address]
            filtered_dict = filtered_df.to_dict()
            print(filtered_dict)
            return render_template("auditor.html", form=form, username=account_address,contract_address=contract_address,isDF = True, filtered_df=filtered_df)
        
        else:
            pass # unknown
    return render_template('auditor.html', form=form, username=account_address)

@app.route('/doctor', methods=['GET', 'POST'])
def doctordash():
    account_address  = request.args.get("address")
    contract_address = request.args.get("contract")
    form = DoctorActions(request.form)
    if request.method == 'POST':
        if request.form.get('action60') == 'VALUE60':
            contract_address  = form.contract_address.data
            return redirect('doctor?'+"address=" + str(account_address) + "&contract=" + str(form.contract_address.data) )
        if request.form.get('action70') == 'VALUE70':
            print("-------------contract address  = " +contract_address)
            isCard  = True
            unique_id = form.print_record.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Doctor printed patient medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)
 
            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.doctor_print_record(unique_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_doctor_print.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")
            record_details  = contract.functions.get_record_details(unique_id).call()
            print(record_details)
            return render_template("doctor.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs, record_details = record_details)

        elif  request.form.get('action90') == 'VALUE90':
            isCard  = True
            unique_id = form.update_record_id.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Doctor updated patient medical records."
            new_record = form.update_record_rec.data
            contract = web3.eth.contract(address = contract_address, abi = abi)
            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.doctor_update_record(unique_id,new_record).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_doctor_update.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            record_details  = contract.functions.get_record_details(unique_id).call()
            print(record_details)
            return render_template("doctor.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs, record_details = record_details)

        elif  request.form.get('action80') == 'VALUE80':
            isCard  = True
            unique_id = form.copy_record.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Doctor copied patient medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)

            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.doctor_copy_record(unique_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_doctor_copy.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")
            record_details  = contract.functions.get_record_details(unique_id).call()
            print(record_details)
            clipboard.copy(record_details)
            return render_template("doctor.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs, record_details = record_details)
        
        elif  request.form.get('action00') == 'VALUE00':
            isCard  = True
            unique_id = form.delete_record.data
            unique_id = unique_id.lower()
            unique_id = Web3.toChecksumAddress(unique_id)
            result = "Doctor deleted patient medical records."

            contract = web3.eth.contract(address = contract_address, abi = abi)

            web3.eth.defaultAccount = account_address
            tx_hash  = contract.functions.doctor_delete_record(unique_id).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            event_logs = contract.events.event_doctor_delete.getLogs()
            print("--------------------changes-------------")
            print(event_logs)
            print("--------------------end changes-------------")

            return render_template("doctor.html", form=form, isCard  = isCard, username=account_address,contract_address=contract_address, result=result, tx_receipt = tx_receipt, tx_hash=tx_hash.hex(), event_logs = event_logs)

        else:
            pass # unknown
    return render_template('doctor.html', form=form, username=account_address)

if __name__ == '__main__':
    # add ssl certificate
    app.run(ssl_context='adhoc')
