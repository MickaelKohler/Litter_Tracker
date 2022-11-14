import os
import io
import pytz
import base64
import logging
import requests
import datetime as dt
from PIL import Image
from dotenv import load_dotenv
import anvil.server
import anvil.media

load_dotenv()

API = 'http://api:8080/'
ANVIL_SERVER = os.getenv('ANVIL_SERVER')
anvil.server.connect(ANVIL_SERVER)


# ============= #
# === LOCAL === #
# ============= #

def img_convert(str_img):
    """
    Convert a binary image in base64 to a BlobMedia
    Anvil will be able to display this BlobMedia on the front-end

    Parameters
    ----------
    str_img: str
        binary image (base64) stored in databse

    Returns
    -------
    anvil BlobMedia object
    """
    try:
        img = Image.open(io.BytesIO(base64.b64decode(str_img)))
        bs = io.BytesIO()
        img.save(bs, format="JPEG")
        return anvil.BlobMedia("image/jpeg", bs.getvalue(), name='anvil_img')
    except Exception as error : 
        logging.error(f'IN img_convert: {error}')


# ======================== #
# === AUTHENTIFICATION === #
# ======================== #

@anvil.server.callable('save_user')
def cookie_creation(data):
    """
    Add user's Token, email, name, time and admin info in the cookie

    Parameters
    ----------
    data: str
        the user's token

    Returns
    -------
    None
    """
    try:
        anvil.server.cookies.local['token'] = data['access_token']
        anvil.server.cookies.local['email'] = data['email']
        anvil.server.cookies.local['name'] = data['name']
        anvil.server.cookies.local['time'] = data['time']
        anvil.server.cookies.local['admin'] = data['admin']
        return None
    except Exception as error : 
        logging.error(f'IN cookie_creation: {error}')

@anvil.server.callable('user')
def token_extraction():
    """
    Extract token, name, email, time and admin in cookie's user

    Parameters
    ----------
    None.

    Returns
    -------
    dict with all informations
    """
    try:
        if token := anvil.server.cookies.local.get('token', None):
            name = anvil.server.cookies.local.get('name', None)
            email = anvil.server.cookies.local.get('email', None)
            time = anvil.server.cookies.local.get('time', None)
            admin = anvil.server.cookies.local.get('admin', False)
            return {'token':token, 'name':name, 'email':email, 'time':time, 'admin':admin}
        else:
            return None
    except Exception as error : 
        logging.error(f'IN token_extraction: {error}')

@anvil.server.callable('login')
def login(email, pwd):
    """
    It takes an email and password, and log in the user in the API
    returns the response from the login endpoint
    
    Parameters
    ----------
    email: str
        the email address of the user
    pwd: str
        the password you want to use
    
    Returns
    -------
    A dictionary with user information
    """
    logging.info("EXE user try to login")
    try:
        login_endpoint = f'{API}/v1/login'
        data = {'email':email, 'password':pwd}
        return requests.get(login_endpoint, data=data).json()
    except Exception as error : 
        logging.error(f'IN login: {error}')    

@anvil.server.callable('register')
def signup(email, pwd, name):
    """
    It takes an email, password, and name, and returns the response from the API when you try to
    register a new user with those credentials
    
    Parameters
    ----------
    email: str
        The email address of the user
    pwd: str
        password of the user
    name: str
        The name of the user

    Returns
    -------
    A JSON object with the following keys:
        - status: 'success' or 'failure'
        - message: 'User created' or 'User already exists'
    """
    logging.info("EXE user try to register a account")
    try:
        register_endpoint = f'{API}/v1/register'
        data = {'email':email, 'password':pwd, 'name':name}
        return requests.post(register_endpoint, data=data).json()
    except Exception as error : 
        logging.error(f'IN signup: {error}')   

@anvil.server.callable('logout')
def logout():
    """
    It clears the cookie user.
    
    Returns
    -------
    None
    """
    try:
        anvil.server.cookies.local.clear()
        logging.info("EXE cookies clear")
        return None
    except Exception as error : 
        logging.error(f'IN logout: {error}')       

@anvil.server.callable('forgot_pwd')
def forgot_password(email):
    """
    This function takes an email address as an argument and returns a JSON object
    and initiate the account recovery procedure when the user has forgot his password.
    
    Parameters
    ----------
    email : str
        email address of the user you want to reset the password for
    
    Returns
    -------
    A JSON object with a message and a status code.
    A email will be send to the user. 
    """
    try:
        forgot_endpoint = f'{API}/v1/password/forgot'
        return requests.get(forgot_endpoint, data={'email':email}).json()
    except Exception as error : 
        logging.error(f'IN forgot_password: {error}')         


# ================ #
# === CLASSIFY === #
# ================ #

@anvil.server.callable('image_classif')
def image_classification(img_uploaded, token=None):
    """
    Send a picture to the L.I.T.T.E.R. Tracker API
    and returns the bin picture for the waste

    Parameters
    ----------
    img_uploaded: Anvil Media Image
        the image send by the user
    token: str (optional)
        user's token   

    Returns
    -------
    Tuple with a str (status) and the JSON (image blob media)

    """
    try:
        image_classif_endpoint = f'{API}/v1/img_classif'
        headers = {"Content-Type": "img/jpeg"}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        with anvil.media.TempFile(img_uploaded) as img:
            data = open(img, 'rb').read()
        r = requests.get(image_classif_endpoint, data=data, headers=headers)
        status = r.json()['status']
        if status != 'success':
            return status, r.json()['msg']
        data = r.json()['data']
        data['image'] = img_convert(data['image'])
        return status, data
    except Exception as error : 
        logging.error(f'IN image_classification: {error}')      

@anvil.server.callable('report_classif')
def report_wrong_classification(class_id, img_uploaded, save_img):
    """
    It sends the image to the server, and tells the server that the image is misclassified
    
    Parameters
    ----------
    class_id: int
        The class id of the class that was incorrectly predicted
    img_uploaded: Anvil Media Image
        The image you want to report
    save_img: bool
        If True, the image will be saved to the database.
    
    Returns
    -------
    Json object with the status: success or fail
    """
    try:
        image_classif_endpoint = f'{API}/v1/img_classif/wrong?class_id={class_id}&save_img={save_img}'
        headers = {"Content-Type": "img/jpeg"}
        with anvil.media.TempFile(img_uploaded) as img:
            data = open(img, 'rb').read()
        r = requests.post(image_classif_endpoint, data=data, headers=headers)
        return r.json()
    except Exception as error : 
        logging.error(f'IN report_wrong_classification: {error}')      


# ================== #
# === STATISTICS === #
# ================== #

@anvil.server.callable('user_history')
def user_history(token):
    """
    Access to the classification history of the user
    
    Parameters
    ----------
    token: str
        the user's JWT token
    
    Returns
    -------
    A dictionarie with the number of classification of each class
    """
    try:
        user_endpoint = f'{API}/v1/user/history'
        headers = {"Content-Type":"img/jpeg", "Authorization":f"Bearer {token}"}
        r = requests.get(user_endpoint, headers=headers)
        return r.json()['data']
    except Exception as error : 
        logging.error(f'IN user_history: {error}') 


# ================ #
# === SETTINGS === #
# ================ #

@anvil.server.callable('delete_user')
def user_delete(token):
    """
    Delete a user account

    Parameters
    ----------
    token: str
        the user's JWT token

    Returns
    -------
    Nothing
    """
    try:
        logging.info("EXE user delete his account")
        user_change_endpoint = f'{API}/v1/user/delete/account'
        headers = {"Authorization": f'Bearer {token}'}
        requests.put(user_change_endpoint, headers=headers)
    except Exception as error : 
        logging.error(f'IN user_delete: {error}') 

@anvil.server.callable('delete_hist')
def user_delete_history(token):
    """
    Delete all classifications history of the user
    
    Parameters
    ----------
    token: str
        the user's JWT token
    
    Returns
    -------
    Nothing
    """
    try:
        logging.info("EXE user delete his history")
        user_change_endpoint = f'{API}/v1/user/delete/account'
        headers = {"Authorization": f'Bearer {token}'}
        requests.put(user_change_endpoint, headers=headers)
    except Exception as error : 
        logging.error(f'IN user_delete_history: {error}')     

@anvil.server.callable('change_name')
def user_change_name(token, name):
    """
    Change the account name of a user
    Modify the data in the cookie
    
    Parameters
    ----------
    token: str
        the user's JWT token
    name: str
        the new user's name
    
    Returns
    -------
    JSON object with the status of the request : success or fail
    """
    try:
        user_change_endpoint = f'{API}/v1/user/change/name'
        headers = {"Authorization": f'Bearer {token}'}
        anvil.server.cookies.local['name'] = name
        return requests.put(user_change_endpoint, headers=headers, data={'name':name}).json()
    except Exception as error : 
        logging.error(f'IN user_change_name: {error}')     

@anvil.server.callable('change_email')
def user_change_email(token, email):
    """
    Change the email of a user
    Change the data and the token in the cookie
    
    Parameters
    ----------
    token: str
        the user's JWT token
    email: str
        the new user's email address
    
    Returns
    -------
    JSON object with the new data of the account
    """
    try:
        user_change_endpoint = f'{API}/v1/user/change/email'
        headers = {"Authorization": f'Bearer {token}'}
        data = requests.put(user_change_endpoint, headers=headers, data={'email':email}).json()
        anvil.server.cookies.local['email'] = email
        anvil.server.cookies.local['token'] = data['new_token']
        return data
    except Exception as error : 
        logging.error(f'IN user_change_email: {error}')    

@anvil.server.callable('change_pwd')
def user_change_password(token, old_pwd, new_pwd):
    """
    Change the password of the account if the old password is equal to 
    the password stored in the database
    
    Parameters
    ----------
    token: str
        the user's JWT token
    old_pwd: str
        the old password
    new_pwd: str
        the new password
    
    Returns
    -------
    JSON object with the request's status : success or fail
    """
    try:
        user_change_endpoint = f'{API}/v1/user/change/password'
        headers = {"Authorization": f'Bearer {token}'}
        data = {'old_password': old_pwd, 'new_password': new_pwd}
        return requests.put(user_change_endpoint, headers=headers, data=data).json()
    except Exception as error : 
        logging.error(f'IN user_change_password: {error}') 

@anvil.server.callable('sub_check')
def user_has_subscribed(token):
    """
    Check if the user has subscribed to the newsletter
    
    Parameters
    ----------
    token: str
        the user's JWT token
    
    Returns
    -------
    a red cross emoji if the user hasn't subscribed, otherwise a green check emoji. 
    """
    try:
        user_change_endpoint = f'{API}/v1/user/subscription'
        headers = {"Authorization": f'Bearer {token}'}
        r = requests.get(user_change_endpoint, headers=headers).json()
        return '❌' if 'not' in r['msg'] else '✅'
    except Exception as error : 
        logging.error(f'IN user_has_subscribed: {error}') 


# =============== #
# === CONTACT === #
# =============== #

@anvil.server.callable('add_msg')
def add_message(name, email, msg, token=None):
    """
    Add a user's message in the database
    
    Parameters
    ----------
    name: str
        the user name
    email: str
        the user email
    msg: str
        the user message
    token: str (optional)
        the user's JWT token
    
    Returns
    -------
    JSON object with the request's status : success or fail
    """
    try:
        msg_endpoint = f'{API}/v1/message'
        headers = {'Connection':'keep-alive'}
        if token:
            headers["Authorization"] = f'Bearer {token}'
        data = {'name': name, 'email': email, 'text': msg}
        return requests.post(msg_endpoint, headers=headers, data=data).json()
    except Exception as error : 
        logging.error(f'IN add_message: {error}') 

@anvil.server.callable('subscribe')
def add_subscription(email):
    """
    Add a user's email address in the Newsletter database
    
    Parameters
    ----------
    email: str
        the user email address
    
    Returns
    -------
    JSON object with the request's status : success or fail
    """
    try:
        sub_endpoint = f'{API}/v1/subscribe'
        return requests.post(sub_endpoint, data={'email': email}).json()
    except Exception as error : 
        logging.error(f'IN add_subscription: {error}') 

@anvil.server.callable('unsubscribe')
def delete_subscription(email):
    """
    Delete the user's email from the Newsletter database
    
    Parameters
    ----------
    email: str
        the user email address
    
    Returns
    -------
    JSON object with the request's status : success or fail
    """
    try:
        sub_endpoint = f'{API}/v1/subscribe'
        return requests.delete(sub_endpoint, data={'email': email}).json()
    except Exception as error : 
        logging.error(f'IN delete_subscription: {error}') 


# ============= #
# === ADMIN === #
# ============= #

@anvil.server.callable("backend-test")
def test_backend_connection():
    """
    Test the back-end connection.
    
    Returns
    -------
    True if the connection is open
    """
    return True

@anvil.server.callable("API-test")
def test_api_connection():
    """
    Test the connection with the API
    
    Parameters
    ----------
    email: str
        the user email address
    
    Returns
    -------
    True if the connection is open, False otherwise 
    """
    r = requests.get(API)
    status = r.json()['status']
    return status == 'success'

@anvil.server.callable('year-hist')
def admin_classif_hist(token):
    """
    Return the number of classificiations for each categories.
    The data is aggregated by month on a one-year rolling
    
    Parameters
    ----------
    token: str
        the admin JWT token
    
    Returns
    -------
    JSON object with each month and the number of classification
    """
    try:
        report_endpoint = f'{API}/v1/admin/year_hist'
        headers = {"Authorization": f'Bearer {token}'}
        return requests.get(report_endpoint, headers=headers).json()
    except Exception as error : 
        logging.error(f'IN admin_classif_hist: {error}')     

@anvil.server.callable('wrong_classif')
def admin_wrong_classification(token, nb_last_classif):
    """
    Return a list of users' wrong classifications.
    For each report :
        - the class
        - the binary image (base64)
        - the classification score
    Limite by the number with nb_last_msg parameter
    
    Parameters
    ----------
    token: str
        the admin JWT token
    nb_last_msg: int
        number of message expected
    
    Returns
    -------
    Dict object with user's email, message, name and emoji  
    """
    try:
        report_endpoint = f'{API}/v1/admin/report?limit={nb_last_classif}'
        headers = {"Authorization":f'Bearer {token}',}
        data = requests.get(report_endpoint, headers=headers).json()['data']
        for item in data:
            item['img'] = img_convert(item['img'])
            item['score'] = round(float(item['score']), 2)
        return data
    except Exception as error : 
        logging.error(f'IN admin_wrong_classification: {error}') 

@anvil.server.callable('nb_wrong_class')
def admin_number_wrong_classification(token):
    """
    Give the number of users' wrong classifications 
    
    Parameters
    ----------
    token: str
        the admin JWT token
    
    Returns
    -------
    integer
    """
    try:
        report_endpoint = f'{API}/v1/admin/report'
        headers = {"Authorization":f'Bearer {token}',}
        return len(requests.get(report_endpoint, headers=headers).json()['data'])
    except Exception as error : 
        logging.error(f'IN admin_number_wrong_classification: {error}') 

@anvil.server.callable('del_report')
def admin_delete_report(token, class_id):
    """
    Delete the report if the image is not a valid report
    
    Parameters
    ----------
    token: str
        the admin JWT token
    class_id: int
        the id of the report
    
    Returns
    -------
    JSON Object with the request's status  
    """
    try:
        report_endpoint = f'{API}/v1/admin/report?class_id={class_id}'
        headers = {"Authorization": f'Bearer {token}'}
        return requests.delete(report_endpoint, headers=headers).json()
    except Exception as error : 
        logging.error(f'IN admin_delete_report: {error}') 

@anvil.server.callable('check_report')
def admin_check_report(token, class_id):
    """
    Change de status of the report if the image is correct
    
    Parameters
    ----------
    token: str
        the admin JWT token
    class_id: int
        the id of the report
    
    Returns
    -------
    JSON Object with the request's status  
    """
    try:
        report_endpoint = f'{API}/v1/admin/report?class_id={class_id}'
        headers = {"Authorization": f'Bearer {token}'}
        return requests.put(report_endpoint, headers=headers).json()
    except Exception as error : 
        logging.error(f'IN admin_check_report: {error}') 

@anvil.server.callable('user_msg')
def admin_user_msg(token, nb_last_msg):
    """
    Return a list of users' messages with.
    For each user :
        - name
        - email address
        - message
        - subscription 
    Limite by the number with nb_last_msg parameter
    
    Parameters
    ----------
    token: str
        the admin JWT token
    nb_last_msg: int
        number of message expected
    
    Returns
    -------
    Dict object with user's email, message, name and emoji  
    """
    try:
        user_msg_endpoint = f'{API}/v1/admin/message?limit={nb_last_msg}'
        headers = {"Authorization": f'Bearer {token}'}
        data = requests.get(user_msg_endpoint, headers=headers).json()['data']
        for item in data:
            item['register'] = '✅' if item['register'] == True else '❌'
        return data
    except Exception as error : 
        logging.error(f'IN admin_user_msg: {error}') 

@anvil.server.callable('nb_msg')
def admin_number_user_msg(token):
    """
    Give the number of users' messages unread
    
    Parameters
    ----------
    token: str
        the admin JWT token
    
    Returns
    -------
    integer
    """
    try:
        user_msg_endpoint = f'{API}/v1/admin/message'
        headers = {"Authorization": f'Bearer {token}'}
        return len(requests.get(user_msg_endpoint, headers=headers).json()['data'])
    except Exception as error : 
        logging.error(f'IN admin_number_user_msg: {error}') 
        
@anvil.server.callable('del_msg')
def admin_delete_msg(token, msg_id):
    """
    It deletes a message from the database.
    
    Parameters
    ----------
    token : str
        the token of the admin
    msg_id: int
        The id of the message you want to delete

    Returns
    -------
    """
    try:
        user_msg_endpoint = f'{API}/v1/admin/message?msg_id={msg_id}'
        headers = {"Authorization":f'Bearer {token}',}
        return requests.delete(user_msg_endpoint, headers=headers).json()
    except Exception as error : 
        logging.error(f'IN admin_delete_msg: {error}') 

@anvil.server.callable('check_msg')
def admin_check_msg(token, msg_id):
    """
    Check a user's message in the API as read
    
    Parameters
    ----------
    token: str
        The token of the admin user 
    msg_id: int
        The id of the message you want to check

    Returns
    -------
    The response is a dictionary with a key of 'message' and a value of 'message checked'
    """
    try:
        user_msg_endpoint = f'{API}/v1/admin/message?msg_id={msg_id}'
        headers = {"Authorization": f'Bearer {token}'}
        return requests.put(user_msg_endpoint, headers=headers).json()
    except Exception as error : 
        logging.error(f'IN admin_check_msg: {error}') 


# ============ #
# === MAIN === #
# ============ #

if __name__ == "__main__":
    launch_time = pytz.timezone('Europe/Paris').localize(dt.datetime.now()).strftime('%Y-%m-%d_%H_%M')
    logging.basicConfig(filename=f"./app/logs/outlogs_{launch_time}.log",level=logging.INFO)
    anvil.server.wait_forever()