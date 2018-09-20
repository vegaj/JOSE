#!/bin/bash
#author: vegaj
privatePEM="$1"
filename=$(basename -- "$privatePEM")
KeyName="${filename%.*}"

if [ -z $privatePEM ] ; then 
    echo "Err: Expected PEM private key."
    exit
fi

echo "Extracting PublicKey in PEM" 
openssl rsa -in $privatePEM -out "${KeyName}pub.pem" -inform PEM -outform PEM

echo "Converting the PEM public key into a ASN.1 PKCS#1 DER format."
ssh-keygen -f "${privatePEM}" -e -m pem > "${KeyName}tmp.pem"

openssl asn1parse -in "${KeyName}tmp.pem" -out "${KeyName}Pub.der"

echo "Converting the PEM Private Key into a ASN.1 PKCS#1 DER format."
openssl asn1parse -in "$privatePEM" -out "${KeyName}.der"

rm "${KeyName}tmp.pem"
rm "${KeyName}pub.pem"


#Refs:
#https://stackoverflow.com/questions/965053/extract-filename-and-extension-in-bash
#https://unix.stackexchange.com/questions/333401/convert-openssh-public-key-to-a-pkcs1-in-hex-format-with-spaces-and-columns (OpenSSH)