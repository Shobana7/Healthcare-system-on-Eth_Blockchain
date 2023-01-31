# System Design 

The proposed system consists of three participants: doctor, patient and auditor. The roles of each of the participants are:

● A patient can book an appointment, print the medical records, give access to a doctor to view the medical records, give access to an audit to view the medical records and delete an appointment.

● A doctor, who has been authorized by the patient, can view the medical records of the patient, copy the records, make changes to the records and delete the records

● An auditor, who has been authorized by the patient, can query the audit logs of the record he/she/they selects and also view the medical records if the audit logs don’t tally.


The main component of the system is the audit logs. Every action performed on a medical record by the participants of the system generates an audit log. It consists of:

● Recorded message: It tells about the action that was carried out. Depending on the action performed, the message in the audit log vans also the status of the record varies.

● Date and time: A timestamp of when the action was performed

● Patient account address: Address of the patient whose record is viewed

● Doctor account address: Address of the doctor who looked after the patient

● Auditor account address: Address of the auditor who views the audit logs

The proposed system contains a front-end for easy user interaction with the system and uses a Flask development web server. The whole system is built over a Blockchain. It uses smart contracts to execute the actions performed on the medical records and also stores the transactions on the blockchain. The smart contract is also written to emit the actions into an event log. This log will be rendered in the front-end for the auditor’s approval.

# Prototype Implementation
To implement the Ethereum Blockchain, Truffle and Ganache are used.

In the Ganache GUI, create a new workspace and add the truffle-config.js file from the project folder

To run the system, create a python virtual environment. Using the commands: (Unix/MacOS)  
                    
                    python3 -m venv env
                    source env/bin/activate
                    
After activating the environment, download the following packages using ‘pip install’ :

❖ Web3.py
❖ Flask
❖ Eth_utils
❖ Hashlib
❖ Cryptography
❖ JSON
❖ Pyopenssl
❖ Pandas
❖ Datetime and Dateutil
❖ Clipboard

Once all the packages are imported, you are all set to run the application. Do the following:

        truffle compile && migrate
in your terminal to migrate all the contracts into the blockchain. 
Then: 
              
        FLASK_APP=main.py FLASK_ENV=development flask run
This will start the web application at https://127.0.0.1:5000.

## Demo

<a href="http://www.youtube.com/watch?v=FcQcT-YqciA" target="_blank"><img src="http://img.youtube.com/vi/FcQcT-YqciA/0.jpg" width="300" height="200"/></a>
