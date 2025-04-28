from flask import Flask, render_template, request, send_file, flash
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField
from AES_self_encryption_with_user import *
import sqlite3

app = Flask(__name__)
# app.config['SECRET_KEY'] = 'key'

# class UploadFileForm(FlaskForm):
#     file = FileField("File to encrypt")
#     submit = SubmitField("Upload a file to encrypt")



# @app.route('/do_secret_recovery', methods=['POST'])
# def do_secret_recovery():
#     secrets = request.form['secret_shares']
#     args = loading_args()
#     args.mode = 'recover_secret'
#     args.callFromGUI = True
#     sedss = self_encryption_decryption_inf_sharing(args)
#     sedss.set_secrets(secrets)
#     sedss.launch()
#     recovered_secret = sedss.recovered_secret
#     result = 'encryption has been done, recovered secrets:'+ recovered_secret
#     return render_template('shares.html', result=result)

# @app.route('/do_secret_recovery_prop', methods=['POST'])
# def do_secret_recovery_prop():
#     secrets = request.form['secret_shares']
#     transaction_num = request.form['transaction_num']
#     args = loading_args()
#     args.mode = 'recover_secret_prop'
#     args.callFromGUI = True
#     args.transaction = transaction_num
#     sedss = self_encryption_decryption_inf_sharing(args)
#     sedss.set_properties(secrets)
#     sedss.launch()
#     recovered_secret = sedss.recovered_secret
#     result = ' '+ recovered_secret
#     return render_template('shares.html', result=result)

@app.route('/do_decrypt', methods=['POST'])
def do_decrypt():
    key = request.form['key']
    userName = request.form['userName']
    userID = request.form['userID']
    n_chunks = request.form['num_chunks']
    chunk_file_name = request.form['chunk_file_name']
    secret_shares = request.form['secret_shares']
    properties = request.form['properties']
    transaction_num = request.form['transaction_num']
    algorithm = request.form['algorithm']
    args = loading_args()
    args.mode = 'decrypt'
    args.callFromGUI = True
    args.key = key
    args.userName = userName
    args.ownerID = userID
    args.numChunks = int(n_chunks)
    args.chunkFile = chunk_file_name
    args.secret_shares = secret_shares
    args.properties = properties
    args.transaction = transaction_num
    args.algorithm = algorithm
    # doing decryption
    sedss, filename = self_encryption_decryption_inf_sharing(args).decrypt_workflow_from_browser()
    result = 'decryption done'
    file = BytesIO()
    file.write(sedss)
    file.seek(0)
    return send_file(
        file,
        as_attachment = True,
        download_name = filename
    )

@app.route('/do_encrypt', methods=['POST'])
def do_encrypt():
    n_chunks = request.form['n_chunks']
    n_secret_pieces = request.form['n_secret_pieces']
    security_level = request.form['security_level']
    sharingUnits = request.form['sharingUnits']
    userName = request.form['userName']
    userID = request.form['userID']
    file = request.files['file']
    algorithm = request.form['algorithm']

    args = loading_args()
    if(file.filename != ''):
        args.mode = 'encrypt_uploaded_file'
        args.numChunks = int(n_chunks)
        args.ownerID = userID
        args.userName = userName
        args.confidentialLevel = int(security_level)
        args.shares = int(n_secret_pieces)
        args.sharingUnits = sharingUnits
        args.workingPath = os.getcwd()
        args.plainTextFileName = file.filename
        args.algorithm = algorithm
        try:
            sedss, hash_array, units = self_encryption_decryption_inf_sharing(args).encrypt_workflow_uploaded_file(file.read())
            result = 'Encryption has been done, your key is: ' + sedss[0]
            for i in range(1, len(sedss)):
                if (units[0] != ''):
                    result += '\nSecret share ' + str(i) + ' (' + units[i-1] + ') is ' + sedss[i]
                else:
                    result += '\nSecret share ' + str(i) + ' is ' + sedss[i]
            if(len(hash_array) > 0):
                result += '\nPASTE THE FOLLOWING HASH VALUES TO A TXT FILE, EACH ONE ON A DIFFERENT LINE! DECRYPTION IS NOT POSSIBLE OTHERWISE, AS YOU HAVE NOT INITIALIZED A DATABASE'
            for j in range(len(hash_array)):
                result += '\n' + hash_array[j]        
            result = result.split('\n')
            return render_template('result.html', result=result)
        except RuntimeError:
            alert = "Please initialize database"
            return render_template('db_alert.html', alert=alert)

    else:
        #update user-specified parameters for encryption
        alert = "Please select a file"
        return render_template('alert.html', alert=alert)
    
@app.route('/start_encryption', methods=['GET'])
def start_encryption():
    return render_template('encrypt.html')

@app.route('/start_decryption', methods=['GET'])
def start_decryption():
    return render_template('decrypt.html')

@app.route('/start_secret_recovery', methods=['GET'])
def start_secret_recovery():
    return render_template('secret_recovery.html')

@app.route('/start_secret_recovery_prop', methods=['GET'])
def start_secret_recovery_prop():
    return render_template('secret_recovery_prop.html')


@app.route('/')
def index():
    return render_template('encrypt.html')

if __name__ == '__main__':
    app.run(port=5001, debug=True)


