from __future__ import absolute_import, division, print_function
import string as st
import random
import sys
import binascii
from nacl.secret import SecretBox
from nacl.encoding import HexEncoder
import math
import collections

key = sys.argv[1]
nonce = sys.argv[2]
isEncrypt = (sys.argv[3] == "encrypt")
paths = sys.argv[4:]

secret_box = SecretBox(key, encoder=HexEncoder)

def get_random_string(length):
    letters = st.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def generate_data(string, time):
    result = ''
    for x in range(time):
        result = result + string
    return result

def get_size(fileobject):
    fileobject.seek(0,2) # move the cursor to the end of the file
    size = fileobject.tell()
    fileobject.seek(0,0)
    return size

def sort_item(item):
    return item[0]

def decrypt_file(paths, nonce):
    name_file_array = []
    keys = []
    hash_item = collections.defaultdict(list)
    for path in paths:
        name_file_array.append(path.split('_'))
    for item in name_file_array:
        key = item[len(item) - 1]
        if (key not in keys): keys.append(key) 
        if (not hash_item[key]):
            hash_item[key] = []
            seperator = '_'
            hash_item[key].append(seperator.join(item))
        else:
            hash_item[key].append(seperator.join(item))
    for key in keys:
        hash_item[key].sort(key = sort_item)
        file_name_split = hash_item[key][0].split('.')
        type_of_file = file_name_split[len(file_name_split) -1]
        new_file_name = file_name_split[0] + '_' + get_random_string(8) + '.' + type_of_file
        result = open(new_file_name, 'w')
        for item in hash_item[key]:
            f = open(item)
            data = f.read()
            data_after = binascii.hexlify(
                secret_box.decrypt(
                    data,
                    binascii.unhexlify(nonce),
                    encoder=HexEncoder,
                )
            )
            result.write(data_after.decode('hex'))
            f.close()
        result.close()

def encrypt_file (paths, nonce):
    for path in paths:
        f = open(path)
        # data = f.read()
        size_of_file = get_size(f)
        divide_number = 1
        if (size_of_file >= 128*pow(1024, 2) and size_of_file < pow(1024, 3)): divide_number = 8
        if (size_of_file >= pow(1024, 3) and size_of_file < pow(1024, 3)*2): divide_number = 16
        key = get_random_string(10)
        for x in range(1, divide_number + 1):
            data = f.read(int(math.ceil(size_of_file/divide_number)))
            data_after = secret_box.encrypt(
                binascii.unhexlify(data.encode('hex')),
                binascii.unhexlify(nonce),
                encoder=HexEncoder,
            ) 
            type_of_file = path.split('.')
            new_file_name = str(x) + '_' + path + '_' + key + '.' +type_of_file[len(type_of_file) -1]
            result = open(new_file_name, 'w')
            result.write(data_after.ciphertext)
            result.close()
        f.close()

if (isEncrypt):
    encrypt_file(paths, nonce)
else: 
    decrypt_file(paths, nonce)
