import sys
import getpass
from cryptography.fernet import Fernet  # type: ignore
import boto3
from dotenv import load_dotenv
import os

# AWS KMS imports (to be added)


# AWS S3 imports (to be added)
# import boto3

# print(sys.argv)

s3 = boto3.client("s3")
load_dotenv()
# bucket name worx
BUCKET_NAME = os.getenv("AWS_BUCKET_NAME")
kms_key_id = os.getenv("KMS_KEY_ID")
kms_client = boto3.client('kms', region_name='us-east-2')

def get():
    email = sys.argv[2]

    while True:
        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm your password: ")
        
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Try again.")

    print(f"{email}")

    response = s3.get_object(Bucket=BUCKET_NAME, Key="message")
    data = response['Body'].read()

    decrypted = kms_client.decrypt(CiphertextBlob=data)

    res = decrypted['Plaintext'].decode()

    print('*** --------- ***')
    print(res)
    print('*** --------- ***')

    # we could get the code to delete the item from the bucket here, but that's not the feature. 

    # keeping it alive is a different thing, they could retrieve the same info as many times as needed within the 5 mins.

    # do we get all and then check which one to retrieve or to retrieve all?

    # first, but first we work on getting and decrypting the val in the browser.

def put():

    email = sys.argv[2]
    # type = sys.argv[3]
    message = sys.argv[3]

    # if type == "-m":
        # message
    # else:
        # file. check file type



    while True:
        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm your password: ")
        
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Try again.")

    print(f"{email}, {message}")
    
    response = kms_client.encrypt(
        KeyId=kms_key_id,
        Plaintext=message
    )

    encrypted = response['CiphertextBlob']

    s3.put_object(Bucket=BUCKET_NAME, Key="message", Body=encrypted)
    print('done!')

command = sys.argv[1]

if command == "get":
    get()
elif command == "put":
    put()
else:
    print('wrong command. run again with get or put.')