import os
import io
import base64
import requests
from PIL import Image
from dotenv import load_dotenv
import anvil.server
import anvil.media

load_dotenv()

API = 'http://api:5000/'
ANVIL_SERVER = os.getenv('ANVIL_SERVER')
anvil.server.connect(ANVIL_SERVER)


# ============= #
# === LOCAL === #
# ============= #

def img_convert(str_img):
    """
    Info
    """
    img = Image.open(io.BytesIO(base64.b64decode(str_img)))
    bs = io.BytesIO()
    img.save(bs, format="JPEG")
    return anvil.BlobMedia("image/jpeg", bs.getvalue(), name='anvil_img')


# ======================== #
# === AUTHENTIFICATION === #
# ======================== #

@anvil.server.callable('save_user')
def token_creation(data):
    """
    Add user's Token in a cookie

    Parameters
    ----------
    data: str
        the user's token

    Returns
    -------
    None

    """
    anvil.server.cookies.local['token'] = data['access_token']
    anvil.server.cookies.local['email'] = data['email']
    anvil.server.cookies.local['name'] = data['name']
    anvil.server.cookies.local['time'] = data['time']
    anvil.server.cookies.local['admin'] = data['admin']
    return None

@anvil.server.callable('user')
def token_extraction():
    """
    Info
    """
    if token := anvil.server.cookies.local.get('token', None):
        name = anvil.server.cookies.local.get('name', None)
        email = anvil.server.cookies.local.get('email', None)
        time = anvil.server.cookies.local.get('time', None)
        admin = anvil.server.cookies.local.get('admin', False)
        return {'token':token, 'name':name, 'email':email, 'time':time, 'admin':admin}
    else:
        return None

@anvil.server.callable('login')
def login(email, pwd):
    """
    Info
    """
    login_endpoint = f'{API}/v1/login'
    data = {'email':email, 'password':pwd}
    return requests.get(login_endpoint, data=data).json()

@anvil.server.callable('register')
def signup(email, pwd, name):
    """
    Info
    """
    register_endpoint = f'{API}/v1/register'
    data = {'email':email, 'password':pwd, 'name':name}
    return requests.post(register_endpoint, data=data).json()

@anvil.server.callable('logout')
def logout():
    """
    Info
    """
    anvil.server.cookies.local.clear()
    return None    

@anvil.server.callable('forgot_pwd')
def forgot_password(email):
    """
    Info
    """
    forgot_endpoint = f'{API}/v1/password/forgot'
    return requests.get(forgot_endpoint, data={'email':email}).json()


# ================ #
# === CLASSIFY === #
# ================ #

@anvil.server.callable('image_classif')
def image_classification(img_uploaded, token=None):
    """
    Send a picture to the L.I.T.T.E.R. Tracker API
    and returns the piscture class of waste

    Parameters
    ----------
    img_uploaded: img
        the image send by the user
    token: str (optional)
        user's token   

    Returns
    -------
    Tuple with a str (status) and the JSON (image blob media)

    """
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

@anvil.server.callable('report_classif')
def report_wrong_classification(class_id, img_uploaded, save_img):
    """
    Info
    """
    image_classif_endpoint = f'{API}/v1/img_classif/wrong?class_id={class_id}&save_img={save_img}'
    headers = {"Content-Type": "img/jpeg"}
    with anvil.media.TempFile(img_uploaded) as img:
        data = open(img, 'rb').read()
    r = requests.post(image_classif_endpoint, data=data, headers=headers)
    return r.json()


# ================== #
# === STATISTICS === #
# ================== #

@anvil.server.callable('user_history')
def user_history(token):
    """
    Info
    """
    user_endpoint = f'{API}/v1/user/history'
    headers = {"Content-Type":"img/jpeg", "Authorization":f"Bearer {token}"}
    r = requests.get(user_endpoint, headers=headers)
    return r.json()['data']


# ================ #
# === SETTINGS === #
# ================ #

@anvil.server.callable('delete_user')
def user_delete(token):
    """
    Info
    """
    user_change_endpoint = f'{API}/v1/user/delete/account'
    headers = {"Authorization": f'Bearer {token}'}
    requests.put(user_change_endpoint, headers=headers)

@anvil.server.callable('delete_hist')
def user_delete_history(token):
    """
    Info
    """
    user_change_endpoint = f'{API}/v1/user/delete/account'
    headers = {"Authorization": f'Bearer {token}'}
    requests.put(user_change_endpoint, headers=headers)

@anvil.server.callable('change_name')
def user_change_name(token, name):
    """
    Info
    """
    user_change_endpoint = f'{API}/v1/user/change/name'
    headers = {"Authorization": f'Bearer {token}'}
    anvil.server.cookies.local['name'] = name
    return requests.put(user_change_endpoint, headers=headers, data={'name':name}).json()

@anvil.server.callable('change_email')
def user_change_email(token, email):
    """
    Info
    """
    user_change_endpoint = f'{API}/v1/user/change/email'
    headers = {"Authorization": f'Bearer {token}'}
    data = requests.put(user_change_endpoint, headers=headers, data={'email':email}).json()
    anvil.server.cookies.local['email'] = email
    anvil.server.cookies.local['token'] = data['new_token']
    return data

@anvil.server.callable('change_pwd')
def user_change_password(token, old_pwd, new_pwd):
    """
    Info
    """
    user_change_endpoint = f'{API}/v1/user/change/password'
    headers = {"Authorization": f'Bearer {token}'}
    data = {'old_password': old_pwd, 'new_password': new_pwd}
    return requests.put(user_change_endpoint, headers=headers, data=data).json()

@anvil.server.callable('sub_check')
def user_has_subscribed(token):
    """
    Info
    """
    user_change_endpoint = f'{API}/v1/user/subscription'
    headers = {"Authorization": f'Bearer {token}'}
    r = requests.get(user_change_endpoint, headers=headers).json()
    return '❌' if 'not' in r['msg'] else '✅'


# =============== #
# === CONTACT === #
# =============== #

@anvil.server.callable('add_msg')
def add_message(name, email, msg, token=None):
    """
    Info
    """
    msg_endpoint = f'{API}/v1/message'
    headers = {'Connection':'keep-alive'}
    if token:
        headers["Authorization"] = f'Bearer {token}'
    data = {'name': name, 'email': email, 'text': msg}
    return requests.post(msg_endpoint, headers=headers, data=data).json()

@anvil.server.callable('subscribe')
def add_subscription(email):
    """
    Info
    """
    sub_endpoint = f'{API}/v1/subscribe'
    return requests.post(sub_endpoint, data={'email': email}).json()

@anvil.server.callable('unsubscribe')
def delete_subscription(email):
    """
    Info
    """
    sub_endpoint = f'{API}/v1/subscribe'
    return requests.delete(sub_endpoint, data={'email': email}).json()


# ============= #
# === ADMIN === #
# ============= #

@anvil.server.callable("backend-test")
def test_backend_connexion():
    "Zone de test"
    return True

@anvil.server.callable("API-test")
def test_api_connexion():
    "Zone de test"
    r = requests.get(API)
    status = r.json()['status']
    return status == 'success'

@anvil.server.callable('year-hist')
def admin_classif_hist(token):
    """
    Info
    """
    report_endpoint = f'{API}/v1/admin/year_hist'
    headers = {"Authorization": f'Bearer {token}'}
    return requests.get(report_endpoint, headers=headers).json()

@anvil.server.callable('wrong_classif')
def admin_wrong_classification(token, nb_last_classif):
    """
    Info
    """
    report_endpoint = f'{API}/v1/admin/report?limit={nb_last_classif}'
    headers = {"Authorization":f'Bearer {token}',}
    data = requests.get(report_endpoint, headers=headers).json()['data']
    for item in data:
        item['img'] = img_convert(item['img'])
        item['score'] = round(float(item['score']), 2)
    return data

@anvil.server.callable('nb_wrong_class')
def admin_number_wrong_classification(token):
    """
    Info
    """
    report_endpoint = f'{API}/v1/admin/report'
    headers = {"Authorization":f'Bearer {token}',}
    return len(requests.get(report_endpoint, headers=headers).json()['data'])

@anvil.server.callable('del_report')
def admin_delete_report(token, class_id):
    """
    Info
    """
    report_endpoint = f'{API}/v1/admin/report?class_id={class_id}'
    headers = {"Authorization": f'Bearer {token}'}
    return requests.delete(report_endpoint, headers=headers).json()

@anvil.server.callable('check_report')
def admin_check_report(token, class_id):
    """
    Info
    """
    report_endpoint = f'{API}/v1/admin/report?class_id={class_id}'
    headers = {"Authorization": f'Bearer {token}'}
    return requests.put(report_endpoint, headers=headers).json()

@anvil.server.callable('user_msg')
def admin_user_msg(token, nb_last_msg):
    """
    Info
    """
    user_msg_endpoint = f'{API}/v1/admin/message?limit={nb_last_msg}'
    headers = {"Authorization": f'Bearer {token}'}
    data = requests.get(user_msg_endpoint, headers=headers).json()['data']
    for item in data:
        item['register'] = '✅' if item['register'] == True else '❌'
    return data

@anvil.server.callable('nb_msg')
def admin_number_user_msg(token):
    """
    Info
    """
    user_msg_endpoint = f'{API}/v1/admin/message'
    headers = {"Authorization": f'Bearer {token}'}
    return len(requests.get(user_msg_endpoint, headers=headers).json()['data'])

@anvil.server.callable('del_msg')
def admin_delete_msg(token, msg_id):
    """
    Info
    """
    user_msg_endpoint = f'{API}/v1/admin/message?msg_id={msg_id}'
    headers = {"Authorization":f'Bearer {token}',}
    return requests.delete(user_msg_endpoint, headers=headers).json()

@anvil.server.callable('check_msg')
def admin_check_msg(token, msg_id):
    """
    Info
    """
    user_msg_endpoint = f'{API}/v1/admin/message?msg_id={msg_id}'
    headers = {"Authorization": f'Bearer {token}'}
    return requests.put(user_msg_endpoint, headers=headers).json()


# ============ #
# === MAIN === #
# ============ #

if __name__ == "__main__":
    anvil.server.wait_forever()