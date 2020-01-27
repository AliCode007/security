#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jan 24 00:46:59 2020

@author: ali
"""

from flask import Flask,request
from ldapOperations import LdapOperations
from server import Server
import json






app = Flask(__name__)
ldapOperations = LdapOperations()
server = Server()

# ldapOperations.add_user('sami','sami','sami')

@app.route("/")
def hello():
    return 'Hello World'

@app.route("/user",methods = ["POST"])
def add_user():
    data = request.get_json()
    print(data)
    certif, key = ldapOperations.add_user(data['commonName'],data['username'],data['password'])
    if certif == None or key == None :
        return {"res" : False }

    return {"res" : True,
            "certif" : certif,
            "key" : key
            }

@app.route('/login',methods=["POST"])
def login():
    data =  request.get_json()
    print(data)
    commonName= data['commonName']
    password = data['password']
    certif = data['certif']
    res,msg = ldapOperations.login(commonName,password,certif)

    return {
        "res" : res,
        "msg" : msg
    }

@app.route('/users',methods=['GET'])
def get_logged_users():
    users = []
    for user in server.connectedUsers :
        public_key=ldapOperations.get_public_key(user)
        info = {
            'user' : user,
            'public_key' : public_key
        }
        users.append(info)
    return {
        "res" :'success',
        'users' : users
    }



if __name__ == "__main__" :
    server.start()
    app.run()
