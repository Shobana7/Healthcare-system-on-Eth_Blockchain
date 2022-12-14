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

● Truffle: Truffle is the development environment, testing framework, and the dApp pipeline for an
EVM blockchain.(https://github.com/trufflesuite/truffle)

● Ganache GUI: Ganache is a personal Ethereum Blockchain used to deploy smart contracts, develop applications, run tests and perform other tasks free of cost. (https://trufflesuite.com/ganache/)
In the Ganache GUI, create a new workspace and add the truffle-config.js file from the project folder

To run the system, create a python virtual environment. Using the commands: (Unix/MacOS)  
                    
                    python3 -m venv env
                    source env/bin/activate
                    
After activating the environment, download the following packages using ‘pip install’ :

❖ Web3.py (https://web3py.readthedocs.io/en/stable/): It is a Python library for interacting with Ethereum. It’s commonly used in decentralized apps (dapps) for sending transactions to the Blockchain, interacting with smart contracts, and many more.

❖ Flask (https://flask.palletsprojects.com/en/2.1.x/quickstart/): Flask is a small and lightweight Python web framework for creating web applications in Python. It is easy to create a web application with Flask because you only need a single Python file.

❖ Eth_utils(https://github.com/ethereum/eth-utils): Used for access the event logs generated by the smart contract from the Blockchain.

❖ Hashlib: Used to hash passwords and file names in /data/

❖ Cryptography: Used for fernet encryption/decryption and generation of key.  

❖ JSON(https://docs.python.org/3/library/json.html): Contract ABI is represented in JSON format. The Contract Application Binary Interface (ABI) is the standard way to interact with contracts in the Ethereum ecosystem, both from outside the blockchain and for contract-to-contract interaction.

❖ Pyopenssl(https://pypi.org/project/pyOpenSSL/):UsedtocreateSSLcertificateforthewebApp.

❖ Pandas(https://pandas.pydata.org/):Usedtostoreandretrievetheencrypteddatain.csvfile.

❖ Datetime(https://docs.python.org/3/library/datetime.html)and Dateutil(https://dateutil.readthedocs.io/en/stable/): to convert human readable time to unix timestamp and vice-versa

❖ Clipboard(https://pypi.org/project/clipboard/): Used in the copy query. It copies a unique patient record into clipboard.

Once all the packages are imported, you are all set to run the application. Do the following:

        truffle compile && migrate
in your terminal to migrate all the contracts into the blockchain. 
Then: 
              
        FLASK_APP=main.py FLASK_ENV=development flask run
This will start the web application at https://127.0.0.1:5000. As you can see the application uses HTTPS.
