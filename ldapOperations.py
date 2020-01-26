#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jan 23 12:06:50 2020

@author: ali
"""
import datetime
import uuid
import subprocess

from ldap3 import Server, Connection, ALL
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

URL = '127.0.0.1'
USER = 'cn=admin,dc=projet,dc=com'
PASS  = 'alio1234'
SEARCH = 'ou=myUsers,cn=admin,dc=projet,dc=com'
GROUP = 'ou=myUsers,cn=admin,dc=projet,dc=com'
CN = 'cn=admin'
FILTER = '(objectclass=inetOrgPerson)'
PROJECT_DIRECTORY = '/home/ali/Desktop/security/'



class LdapOperations :
    def __init__(self):
        self.conn = None
        self.loggedUsers = []
        self.connect()
    
    def connect(self):
        server = Server(URL,get_info=ALL)
        self.conn = Connection(server,USER,PASS,auto_bind=True)
        self.conn.bind()
        
        
    def add_user(self,commonName,username,password):
        test = self.conn.add('cn={},ou=myUsers,cn=admin,dc=projet,dc=com'.format(commonName), ['inetOrgPerson','top'],
                {'objectClass': 'person', 'sn': username , 'userPassword':password})
        print(test)
        if test :
            return self.generate_selfsigned_cert(commonName)
        else : 
            return None,None
        
    def delete_user(self,commonName):
        dn = "cn={},ou=myUsers,cn=admin,dc=projet,dc=com".format(commonName)
        res = self.conn.delete(dn)
        print(res)



    def get_all_users(self):
        self.conn.search(SEARCH,FILTER)
        #print(self.conn.entries)
    
    def check_login_infos(self,commonName,password):
        commonName = commonName.strip()
        password = password.strip()
        filterr = '(&(cn={0})(userPassword={1}))'.format(commonName,password)
        self.conn.search(SEARCH,filterr)
        #print(self.conn.entries)
        return len(self.conn.entries) > 0
    
    def check_certificate(self,cn,certif_string):
        with open('{}tmp/{}.crt'.format(PROJECT_DIRECTORY,cn), 'wb') as f:
            f.write(str.encode(certif_string))
        completedProcess = subprocess.run('openssl verify -CAfile {}ca/ca.crt {}tmp/{}.crt'.format(PROJECT_DIRECTORY,PROJECT_DIRECTORY,cn), shell=True)
        return completedProcess.returncode == 0
        
    def generate_selfsigned_cert(self,cn):  
         key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
        )

         public_key = key.public_key()
         pem = public_key.public_bytes(
             encoding = serialization.Encoding.PEM,
             format = serialization.PublicFormat.SubjectPublicKeyInfo)
         #write our public to disk
         with open("{}rsa_keys/{}public_key.pem".format(PROJECT_DIRECTORY,cn),"wb") as f :
             f.write(pem)

         key_pem =key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
            )
         # Write our private key to disk for safe keeping
         with open("{}rsa_keys/{}_Key.pem".format(PROJECT_DIRECTORY,cn), "wb") as f:
             f.write(key_pem)
        
         # Generate a CSR
         csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"INSAT"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"INSAT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, cn),
        x509.NameAttribute(NameOID.COMMON_NAME, cn+'@insat.com'),
        ])).add_extension(
        x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.DNSName(cn+'@insat.com')
        ]),
        critical=False,
        # Sign the CSR with our private key.
        ).sign(key, hashes.SHA256(), default_backend())
        # Create the client certificate
         pem_cert = open('{}ca/ca.crt'.format(PROJECT_DIRECTORY),'rb').read()
         ca = x509.load_pem_x509_certificate(pem_cert, default_backend())
         #print(ca)
         pem_key = open('{}ca/ca.key'.format(PROJECT_DIRECTORY),'rb').read()
         ca_key = serialization.load_pem_private_key(pem_key, password=None, backend=default_backend())
         #print(ca_key) 
        
         builder = x509.CertificateBuilder()
         builder = builder.subject_name(csr.subject)
         builder = builder.issuer_name(ca.subject)
         builder = builder.not_valid_before(datetime.datetime.now()+datetime.timedelta(-1))
         builder = builder.not_valid_after(datetime.datetime.now()+datetime.timedelta(7))
         builder = builder.public_key(csr.public_key())
         builder = builder.serial_number(int(uuid.uuid4()))
         for ext in csr.extensions:
             builder.add_extension(ext.value, ext.critical)
        
         certificate = builder.sign(
         private_key=ca_key,
         algorithm=hashes.SHA256(),
         backend=default_backend()
         )
         with open('{}certificates/{}.crt'.format(PROJECT_DIRECTORY,cn), 'wb') as f:
             f.write(certificate.public_bytes(serialization.Encoding.PEM))
         return certificate.public_bytes(serialization.Encoding.PEM),key_pem

    def login(self,commonName,password,certif):
        if self.check_login_infos(commonName,password) == False :
            return False,'Wrong Password'
        if self.check_certificate(commonName,certif) == False :
            return False,'Invalid Certificate'
        return True,'you are logged'
    def get_public_key(self,commonName):
        public_key = open("{}rsa_keys/{}public_key.pem".format(PROJECT_DIRECTORY, commonName), "rb").read()
        # public_key = serialization.load_pem_public_key(pem_key,backend=default_backend())
        return public_key


 
        
             
         
    

# ldapOperations = LdapOperations()
# ldapOperations.connect()
# ldapOperations.add_user('ali','ali','ali')
# ldapOperations.add_user('hamdi','hamdi','hamdi')
# # =============================================================================
# # ldapOperations.add_user('ali','ali','ali')
# # =============================================================================
# certif,key =ldapOperations.add_user('ali','ali','ali')
# print(certif)
# print(key)
#
# #ldapOperations.get_all_users()
# # =============================================================================
# print(ldapOperations.check_login_infos('ali','ali'))
# # ldapOperations.generate_selfsigned_cert('hamza')
# #

