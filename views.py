from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
import numpy as np
import base64
import os
from datetime import datetime
from hashlib import sha256
import pyaes, pbkdf2, binascii, secrets
import json
from web3 import Web3, HTTPProvider

global username, usersList, verify_list, accessList
global contract, web3

#function to call contract
def getContract():
    global contract, web3
    blockchain_address = 'http://127.0.0.1:9545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'ZTNA.json' #ZTNA contract file
    deployed_contract_address = '0xD1487D827BA83C0ca1B94269068791E71200C8d4' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
getContract()

def getUsersList():
    global usersList, contract
    usersList = []
    count = contract.functions.getUserCount().call()
    for i in range(0, count):
        user = contract.functions.getUsername(i).call()
        password = contract.functions.getPassword(i).call()
        phone = contract.functions.getPhone(i).call()
        email = contract.functions.getEmail(i).call()
        address = contract.functions.getAddress(i).call()
        usersList.append([user, password, phone, email, address])

def getVerifyList():
    global verify_list, contract
    verify_list = []
    count = contract.functions.getFileCount()().call()
    for i in range(0, count):
        owner = contract.functions.getOwner(i).call()
        filename = contract.functions.getFilename(i).call()
        hashcode = contract.functions.getHash(i).call()
        role = contract.functions.getRole(i).call()
        verify_list.append([owner, filename, hashcode, role])

def getAccess():
    global accessList, contract
    accessList = []
    count = contract.functions.getAccessCount()().call()
    for i in range(0, count):
        user = contract.functions.getAccessUser(i).call()
        activity = contract.functions.getActivity(i).call()
        activity_time = contract.functions.getActivityTime(i).call()
        accessList.append([user, activity, activity_time])        

getUsersList()
getVerifyList()#get list of verification users
getAccess() #get list of users whose attribute has permission to access data

def getAESKey(): #generating AES key based on Diffie common secret shared key
    password = "s3cr3t*c0d3"
    passwordSalt = str("0986543")#get AES key using diffie
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def encryptAES(plaintext): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(getAESKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decryptAES(enc): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(getAESKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def UploadFileAction(request):
    if request.method == 'POST':
        global username
        global verify_list, accessList
        myfile = request.FILES['t1'].read()
        fname = request.FILES['t1'].name
        role = request.POST.get('t2', False)
        if os.path.exists("ZeroTrustApp/static/files/"+fname):
            os.remove("ZeroTrustApp/static/files/"+fname)
        
        file_encrypt = encryptAES(myfile)
        with open("ZeroTrustApp/static/files/"+fname, "wb") as file:
            file.write(file_encrypt)
        file.close()
        hashcode = sha256(file_encrypt).hexdigest()
        upload_time = str(datetime.now())

        msg = contract.functions.saveFile(username, fname, hashcode, role).transact()
        tx_receipt = web3.eth.waitForTransactionReceipt(msg)
        verify_list.append([username, fname, hashcode, role])

        msg1 = contract.functions.saveAccess(username, "File upload "+fname, upload_time).transact()
        tx_receipt1 = web3.eth.waitForTransactionReceipt(msg1)
        accessList.append([username, "File upload "+fname, upload_time])        
        status = '<font size="3" color="blue">Blockchain Data Hashcode = '+str(hashcode)+"</font><br/>"
        status += str(tx_receipt)
        context= {'data':status}
        return render(request, 'UploadFile.html', context)

def Download(request):
    if request.method == 'GET':
        global accessList, username
        name = request.GET.get('requester', False)
        with open("ZeroTrustApp/static/files/"+name, "rb") as file:
            data = file.read()
        file.close()        
        aes_decrypt = decryptAES(data)
        upload_time = str(datetime.now())
        msg1 = contract.functions.saveAccess(username, "File Download "+name, upload_time).transact()
        tx_receipt1 = web3.eth.waitForTransactionReceipt(msg1)
        accessList.append([username, "File Download "+name, upload_time])
        response = HttpResponse(aes_decrypt,content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename='+name
        return response          

def ViewActivities(request):
    if request.method == 'GET':
        global username, accessList
        output = '<table border=1 align=center width=100%><tr><th><font size="3" color="black">Access Username</th><th><font size="3" color="black">Activities</th>'
        output+='<th><font size="3" color="black">Activities Date & Time</th></tr>'
        
        for i in range(len(accessList)):
            al = accessList[i]
            output += '<tr><td><font size="" color="black">'+str(al[0])+'</td><td><font size="" color="black">'+al[1]+'</td>'
            output+='<td><font size="3" color="black">'+al[2]+'</td></tr>'
        output += "</table><br/><br/><br/><br/>"    
        context= {'data':output}
        return render(request, 'UserScreen.html', context)      


def AccessData(request):
    if request.method == 'GET':
        global username, verify_list, accessList
        output = '<table border=1 align=center width=100%><tr><th><font size="3" color="black">Owner Name</th><th><font size="3" color="black">File Name</th>'
        output+='<th><font size="3" color="black">Blockchain Verification Hash</th><th><font size="3" color="black">Access Role</th><th><font size="3" color="black">Download File</th></tr>'
        #get list of verified users to allow access to that
        for i in range(len(verify_list)):
            vl = verify_list[i]
            output += '<tr><td><font size="" color="black">'+str(vl[0])+'</td><td><font size="" color="black">'+vl[1]+'</td>'
            output+='<td><font size="3" color="black">'+vl[2]+'</td><td><font size="3" color="black">'+vl[3]+'</td>'
            #if given file has public access then allow user to download the file
            if vl[3] == "Public":
                output +='<td><a href=\'Download?requester='+vl[1]+'\'><font size=3 color=green>Download</font></a></td></tr>'
            else: #if file is private then it will restrict access to other user but its owner can acces that file
                if vl[0] == username:
                    output +='<td><a href=\'Download?requester='+vl[1]+'\'><font size=3 color=green>Download</font></a></td></tr>'
                else:
                    output+='<td><font size="3" color="red">Private (Access Restricted)</td></tr>'
        output += "</table><br/><br/><br/><br/>"    
        context= {'data':output}
        return render(request, 'UserScreen.html', context)      

def UploadFile(request):
    if request.method == 'GET':
        return render(request, 'UploadFile.html', {})

def UserLogin(request):
    if request.method == 'GET':
        return render(request, 'UserLogin.html', {})

def index(request):
    if request.method == 'GET':
        return render(request, 'index.html', {})

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})

def RegisterAction(request):
    if request.method == 'POST':
        global usersList
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        count = contract.functions.getUserCount().call()
        status = "none"
        for i in range(0, count):
            user1 = contract.functions.getUsername(i).call()
            if username == user1:
                status = "exists"
                break
        if status == "none":
            msg = contract.functions.saveUser(username, password, contact, email, address).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(msg)
            usersList.append([username, password, contact, email, address])
            context= {'data':'<font size="3" color="blue">Signup Process Completed</font><br/>'+str(tx_receipt)}

            upload_time = str(datetime.now())
            msg1 = contract.functions.saveAccess(username, "Registered with Blockchain", upload_time).transact()
            tx_receipt1 = web3.eth.waitForTransactionReceipt(msg1)
            accessList.append([username, "Registered with Blockchain", upload_time])
        
            return render(request, 'Register.html', context)
        else:
            context= {'data':'Given username already exists'}
            return render(request, 'Register.html', context)

def UserLoginAction(request):
    if request.method == 'POST':
        global username, contract, usersList
        username = request.POST.get('username', False)
        password = request.POST.get('password', False)
        status = 'none'
        for i in range(len(usersList)):
            ulist = usersList[i]
            user1 = ulist[0]
            pass1 = ulist[1]            
            if user1 == username and pass1 == password:
                status = "success"
                break
        if status == 'success':
            upload_time = str(datetime.now())
            msg1 = contract.functions.saveAccess(username, "Login to Blockchain", upload_time).transact()
            tx_receipt1 = web3.eth.waitForTransactionReceipt(msg1)
            accessList.append([username, "Login to Blockchain", upload_time])
            output = 'Welcome '+username
            context= {'data':output}
            return render(request, "UserScreen.html", context)
        if status == 'none':
            context= {'data':'Invalid login details'}
            return render(request, 'UserLogin.html', context)

