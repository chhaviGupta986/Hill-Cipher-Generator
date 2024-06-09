from flask import Flask, request,  render_template, url_for, redirect, session
import string
import numpy as np
import math
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField

app = Flask(__name__)
app.config['SECRET_KEY'] = "secret"
special="!@#$%^&*()_+-=~`<>?,./:\";'[]{}\| " #special characters
# valid=string.ascii_uppercase+string.digits+special
#valid= set of all possible characters including alphabets, digits, and special characters
#user not restricted to enter only alphabets, they may enter anything

valid=string.ascii_uppercase #can uncomment for testing 
#(to tally output with gfg bcus they considered only alphabets)

total_chars=len(valid)

def batch_size(keyword): 
    #how many characters can be processed (encrypted/decrypted) in one go
    #text has to be divided into batches of batch size 'n' and encrypted/decrypted
    keylen=len(keyword)
    n=int(math.sqrt(keylen)) #key matrix should be square always
    #hence finding out the closest square number to length of key
    if(n*n)!=keylen:
        n+=1
    return n

def convert_keyword_to_word_matrix(keyword):
    keyword=keyword.upper() #all letter should be capitalised for uniformity
    keylen=len(keyword)
    n=batch_size(keyword)
    sqr=n*n
    add=keyword[-1]*(sqr-keylen) #this is the padding that we will add to the keyword
    #to make its length equal to closest square number i.e. sqr
    # print("debug..adding",add," to make it of size",sqr)
    keyword_copy=(keyword+add) #modifying copy of keyword not keyword directly
    #bcus user input should not be directly modified (bad practice)
    key_arr=[ch for ch in keyword_copy] #converting string into list of characters
    key_arr=np.array(key_arr) #convert to numpy array
    key_arr=key_arr.reshape(-1,n) #Reshaping it as 2d array with n columns
    return key_arr

def convert_text_to_word_matrix(keyword,text):
    text = text.replace('\x00', '') #removing null characters
    '''null characters have been introduced due to some previous steps perhaps while converting
    array of character to string. was getting error because of null char presence.these null chars 
    arent visible while printing hence took me long time to spot them. realised they were there when 
    i printed length of text and it was more than the number of chars i could see'''
    n=batch_size(keyword)
    rem=len(text)%n
    if(rem!=0):
        #padding needed if text length is too short 
        #(smaller than batch size or not a multiple of batch size)
        pad=(n-rem)
        text_copy=text+('z'*pad) #padding with zeroes, can pad with anything
        '''
        DONT PAD WITH 0..DO Z INSTEAD, BECAUSE IT CAUSES ERROR WHEN
        ACCEPTABLE CHARACTER SET IS ONLY ALPHABETS!!!
        '''

    else:
        text_copy=text    

    text_copy=text_copy.upper()
    text_arr=[ch for ch in text_copy] #converting string to list of chars
    text_arr=np.array(text_arr)
    text_arr=text_arr.reshape(-1,n) #reshaping as 2d matrix with n columns 
    #and how many ever rows needed accordingly (-1)
    return text_arr

#below 4 functions use the syntax fxn2=np.vectorize(fxn1) 
#what it means is that when fxn2 is called on any matrix
#the 'fxn1' gets performed on each element of the matrix
#thats all, no big deal.
convert_to_mod_valid=np.vectorize(lambda x:x%total_chars)
def convert_to_numeric(x):
    # print("hi, valid=",valid)
    # print(f"entered convert_to_numeric with x= {x}")
    try:
        return valid.index(x)
    except ValueError:
        # print(f"ouch,error: {ValueError}\n")
        # Handle the case where the character is not found in the valid string
        return -1  # Or any other suitable handling mechanism

convert_to_numeric = np.vectorize(convert_to_numeric)


# convert_to_numeric=np.vectorize(lambda x:valid.index(x))
convert_to_chars=np.vectorize(lambda x:valid[x])
round_off=np.vectorize(lambda x:int(np.rint(x)))

def convert_to_numeric_key_array(key_arr):
    # print("inside convert_to_numeric_key_array..with key_arr=",key_arr)
    key_arr_numeric=convert_to_numeric(key_arr)
    # print("key_arr_numeric\n",key_arr_numeric)
    return key_arr_numeric
def convert_to_numeric_text_arr(text_arr):
    # print("inside convert_to_numeric_text_array..with text_arr=",text_arr)
    text_arr_numeric=convert_to_numeric(text_arr)
    #transposing to make it a column matrix
    text_arr_numeric=text_arr_numeric.T
    return text_arr_numeric

def check_determinant_of_encryption_key(key_arr_numeric):
    
    det=np.linalg.det(key_arr_numeric)
    det=round(det)
    if det<0:
        det=det%total_chars #if negative det, then mod it n make it positive
    #Rule:
        #The determinant of the encryption key matrix should be relatively prime 
        #to the length of valid character set. i.e. total_chars variable
    #Hence check gcd
    if math.gcd(det,total_chars)!=1:
        print("if gcd not 1...det=",det)
        message = "Determinant not co-prime to 26. Please try a different key"
        return False, message
    else:
        mod_inverse(det,total_chars)
        message = "Encryption can proceed with this key"
        return True, message
    
def multiply(key_arr_numeric, text_arr_numeric):
    # print(f"debug...entered multiply with key_arr_numeric={key_arr_numeric} n text_Arr_numeric={text_arr_numeric}")
    result=np.dot(key_arr_numeric,text_arr_numeric)
    result=convert_to_mod_valid(result)
    return result

def encrypt(keyword,text):
    try:
        key_arr=convert_keyword_to_word_matrix(keyword)
        text_arr=convert_text_to_word_matrix(keyword,text)
        key_arr_numeric=convert_to_numeric_key_array(key_arr)
        text_arr_numeric=convert_to_numeric_text_arr(text_arr)

        isvalidkey, message =check_determinant_of_encryption_key(key_arr_numeric)
        encrypted = ""
        if not isvalidkey:
            return encrypted,message
        # result=multiply(key_arr_numeric, text_arr_numeric)
    except:
        message="Invalid input entered! Please check that there are only alphabets and no whitespaces in your input."
        # print("some new error")
        return "",message
    try:
        result=multiply(key_arr_numeric, text_arr_numeric)
        char_arr=convert_to_chars(result)
        char_arr=char_arr.T
        # flat_char_arr = char_arr.flatten()
        # encrypted = ''.join(str(ch) for ch in flat_char_arr)
        encrypted=char_arr.tobytes().decode('utf-8') #converting char arr to string
        return encrypted, message
    except ValueError as v1:
        # print("error v1 in multiply",v1)
        return "", "Unexpected error"


    
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    message = ""
    if gcd != 1:
        message = "Matrix not invertible, try a different key"
        return -1,message
    return x % m, message

def create_decrypt_key(keyword):
        key_arr=convert_keyword_to_word_matrix(keyword)
        key_arr_numeric=convert_to_numeric_key_array(key_arr)
        det = round_off(np.linalg.det(key_arr_numeric))
        # print(f"inside create_Decrypt_key...det={det}")
        message = ""
        arr=[["-"]]
        if det < 0:
            det = det % (total_chars)
            # print(f"inside if ..new det={det}")
        elif det==0:
            message = "Decryption wont work with this keyword, please try again with different key."
            return arr, message
        det_inv, message = mod_inverse(det,total_chars)
        if det_inv==-1:
            return arr,message

        #modular multiplicative inverse
        #refer: https://www.youtube.com/watch?v=JK3ur6W4rvw&ab_channel=NesoAcademy
        #timestamp around 20:27
        inv_key = (
            det_inv
            * np.linalg.det(key_arr_numeric)
            * np.linalg.inv(key_arr_numeric)
        )
        inv_key=convert_to_mod_valid(inv_key) 
        return round_off(inv_key), message 

def decrypt(keyword,cipher):
    try:
        dec_key, message =create_decrypt_key(keyword)
        if isinstance(dec_key, np.ndarray) and dec_key.shape == (1, 1):
            dec_key = dec_key[0][0]  # Extract the single value from the array
            if dec_key == -1:
                return "", message
        cipher_arr=convert_text_to_word_matrix(keyword,cipher)
        cipher_arr_numeric=convert_to_numeric_text_arr(cipher_arr)
    except ValueError as v:
        # print(f"error in decrypting:{v}")
        message="Invalid input entered! Please check that there are only alphabets and no whitespaces in your input."
        return "",message
    except:
        message="Unexpected error"
        # print("some new error")
        return "",message
    try:
        result=multiply(dec_key, cipher_arr_numeric)
    except ValueError as v1:
        # print("error v1 in multiply",v1)
        return "", "Matrix not invertible, try a different key"
    try:
        result=round_off(result)

        result=convert_to_mod_valid(result)
        char_arr=convert_to_chars(result)
        char_arr=char_arr.T
        decrypted=""
        #below for loop is for converting 2d matrix to string
        for i in char_arr: 
            for j in i:
                decrypted+=j
    except:
        message="Unexpected error"
        # print("some new error")
        return "",message
    return decrypted, message

@app.route('/')
def get_response():
    return render_template("home.html")

class EncryptionForm(FlaskForm):
    keyword = StringField("Enter the keyword to be used: ")
    text = StringField("Enter the text to be encrytped: ")
    submit = SubmitField("Submit")

class DecryptionForm(FlaskForm):
    keyword = StringField("Enter the keyword to be used: ")
    cipher = StringField("Enter the text to be decrypted: ")
    submit = SubmitField("Submit")

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypting():
    keyword = None
    text = None
    form = EncryptionForm()

    if form.validate_on_submit():
        keyword = form.keyword.data
        form.keyword.data = ''
        
        text = form.text.data
        form.text.data = ''
        
        encrypted_text = encrypt(keyword, text)
        session['encrypted_text'] = encrypted_text  # Store in session
        session['original_text'] = text  # Store in session
        session['keyword'] = keyword  # Store in session
        return redirect(url_for('result'))
        
    return render_template("encrypt.html", keyword=keyword, text=text, form=form)


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypting():
    keyword = None
    cipher = None
    form = DecryptionForm()

    if form.validate_on_submit():
        keyword = form.keyword.data
        form.keyword.data = ''
        
        cipher = form.cipher.data
        form.cipher.data = ''

        decrypted_text = decrypt(keyword, cipher)
        session['encrypted_text'] = decrypted_text  # Store in session
        session['original_text'] = cipher  # Store in session
        session['keyword'] = keyword  # Store in session
        return redirect(url_for('result'))
        
    return render_template("decrypt.html", keyword=keyword, cipher=cipher, form=form)



@app.route('/result')
def result():
    encrypted_text = session.pop('encrypted_text', None)  # Retrieve from session
    temp = encrypted_text[1]

    if temp != 'Determinant not co-prime to 26. Please try a different key' or "Decryption wont work with this keyword, please try again with different key." or "Matrix not invertible, try a different key":
        encrypted_text1 = encrypted_text[0]
        
    else:
        encrypted_text1 = ''

    if temp == 'Determinant not co-prime to 26. Please try a different key' or temp=='Unexpected error' or temp== "Invalid input entered! Please check that there are only alphabets and no whitespaces in your input.":
        encrypted_text2 = temp
    elif temp == "Decryption wont work with this keyword, please try again with different key.":
        encrypted_text2 = temp
    elif temp == "Matrix not invertible, try a different key":
        encrypted_text2 = temp
    else:
        encrypted_text2 = ''

    original_text = session.pop('original_text', None)
    keyword = session.pop('keyword', None)

    if request.method == 'POST':
        return render_template("home.html")
    return render_template("result.html", encrypted_text1=encrypted_text1, encrypted_text2=encrypted_text2, keyword = keyword, original_text=original_text)

if __name__ == '__main__':
    app.run()
