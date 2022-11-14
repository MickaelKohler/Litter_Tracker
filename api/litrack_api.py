import os
import re
import pytz
import base64
import imghdr
import logging
import psycopg2 
import tempfile
import contextlib
import datetime as dt
from dateutil.relativedelta import relativedelta
from functools import wraps
import numpy as np
import pandas as pd
import tensorflow as tf
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, verify_jwt_in_request, get_jwt, get_jwt_identity
from waitress import serve
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = dt.timedelta(days=30)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = "litter.tracker.project@gmail.com"
DB_USER = os.getenv('DB_USER')
DB_PWD = os.getenv('DB_PWD')
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)


# ======================= #
# === LOCAL FONCTIONS === #
# ======================= # 

def db_connect(sql_querie, variable=(None, ), output=True):
    """
    Create a connection between the API and the database.

    Parameters
    ----------
    sql_querie: str
        An SQL query
    variable: tuple of str, optional
        tuple with all variables that will be added in the query 
    output: bool, optional
        True if the query returns a value, False otherwise

    Returns
    -------
    All rows of the query result are returned in a list of tuples
    """
    logging.info("EXE request in database")
    try : 
        conn = psycopg2.connect(
            host="database", 
            port=5432, 
            database="LITRACK", 
            user=DB_USER, 
            password=DB_PWD)
        cur = conn.cursor()
        cur.execute(sql_querie, variable)
        tab = cur.fetchall() if output else None
        conn.commit()
        cur.close(); conn.close()
        return tab
    except Exception as error : 
        logging.error(f'IN db_connect: {error}')

def email_check(email):
    """
    Check in the LT_USER table if the user is registered

    Parameters
    ----------
    email: str
        user's email address

    Returns
    -------
    Dict Object with the user_id
    """
    logging.info("EXE email_check")
    try:
        sql="""
            SELECT
                user_id
            FROM
                lt_user
            WHERE
                user_mail = %s;
            """
        return db_connect(sql, (email, ), output=True)
    except Exception as error:
        logging.error(f'IN email_check: {error}')

def email_valid(email):
    """
    Check if the eamil is valid

    Parameters
    ----------
    email: str
        user's email address

    Returns
    -------
    booleen: True if the email address is valid, false otherwise
    """
    logging.info("EXE email_valid")
    try:
        mail_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return bool(re.fullmatch(mail_regex, email))
    except Exception as error:
        logging.error(f'IN email_check: {error}')

def pwd_valid(pwd):
    """
    Check if the password is strong enough.
    He must have:
        - more than 8 characters,
        - at least a number,
        - at least a capital letter,
        - at least one special character

    Parameters
    ----------
    pwd: str
        user's password

    Returns
    -------
    Booleen: True if the password is strong, false otherwise
    """
    logging.info("EXE pws_valid")
    try:
        return bool(len(pwd) > 8 and re.search('[0-9]', pwd) and re.search('[A-Z]', pwd) and re.search('[!?$%]', pwd))
    except Exception as error:
        logging.error(f'IN pws_valid: {error}')

def classid_unknown(class_id):
    """
    Check if the classification is present in the LT_REPORT database

    Parameters
    ----------
    class_id: int
        classification identifier

    Returns
    -------
    Booleen: True if the request's response is empty
    """
    try:
        sql="""
            SELECT
                class_id
            FROM
                lt_report
            WHERE
                class_id = %s;
            """
        return len(db_connect(sql, (class_id, ), output=True)) == 0
    except Exception as error:
        logging.error(f'IN classid_unknown: {error}')

def msgid_unknown(msg_id):
    """
    Check if the message is present in the LT_MESSAGE database

    Parameters
    ----------
    msg_id: int
        message id

    Returns
    -------
    Booleen: True if the request's response is empty
    """
    try: 
        sql="""
            SELECT
                msg_id
            FROM
                lt_message
            WHERE
                msg_id = %s;
            """
        return len(db_connect(sql, (msg_id,), output=True)) == 0
    except Exception as error:
        logging.error(f'IN msgid_unknown: {error}')

def add_user(email, name, password, admin):
    """
    Add a user in the LT_USER table in the database

    Parameters
    ----------
    email: str
        user's email address
    name: str
        user's email address
    password: str
        user's email address
    admin: bool
        True if the user is admin, False otherwise

    Returns
    -------
    Nothing
    """
    logging.info("EXE add_user in database")
    try:
        sql="""INSERT INTO lt_user(user_mail, user_pwd, user_name, user_admin, user_datetime)
            VALUES(%s, %s, %s, %s, NOW());"""
        db_connect(sql, (email, password, name, admin), output=False)    
    except Exception as error:
        logging.error(f'IN add_user: {error}')

def change_pwd(user_id, password):
    """
    Change the user's password stored in LT_USER table

    Parameters
    ----------
    user_id: int
        user identifier
    password: str
        user's password
  
    Returns
    -------
    Nothing
    """
    try:
        sql="""
            UPDATE lt_user
            SET user_pwd = %s
            WHERE user_id = %s;"""
        db_connect(sql, (password, user_id), output=False) 
    except Exception as error:
        logging.error(f'IN change_pwd: {error}')

def change_email(user_id, email):
    """
    Change the user's email address stored in LT_USER table

    Parameters
    ----------
    user_id: int
        user identifier
    email: str
        user's email address
  
    Returns
    -------
    Nothing
    """
    try:
        sql="""
            UPDATE lt_user
            SET user_mail = %s
            WHERE user_id = %s;
            """
        db_connect(sql, (email, user_id), output=False)
    except Exception as error:
        logging.error(f'IN change_email: {error}')  

def change_name(user_id, name):
    """
    Change the user's name account stored in LT_USER table

    Parameters
    ----------
    user_id: int
        user identifier
    name: str
        user's name account
  
    Returns
    -------
    Nothing
    """
    try:
        sql="""
            UPDATE lt_user
            SET user_name = %s
            WHERE user_id = %s;
            """
        db_connect(sql, (name, user_id), output=False) 
    except Exception as error:
        logging.error(f'IN change_name: {error}')  

def check_user(email, password):
    """
    Compares the user's password with the one stored in LT_USER database
    If the password is right, return the user id, name, email and admin statut,
    otherwise, return False.

    Parameters
    ----------
    email: str
        user's email
    password: str
        user's password

    Returns
    -------
    A list if passwords match, otherwise False

    """
    try:
        sql="""
            SELECT
                user_id,
                user_name,
                user_pwd,
                user_datetime,
                user_admin
            FROM
                lt_user
            WHERE
                user_mail = %s; 
            """
        output = list(db_connect(sql, (email, ), output=True))
        output = output[0]
        if check_pwd := bcrypt.check_password_hash(output[2], password):
            return (output[0], output[1], output[3], output[4])
        else:
            return False
    except Exception as error:
        logging.error(f'IN check_user: {error}')  

def report_time_limit(class_id):
    """
    Checks in database if the classification was made less than 2 minutes.
    After this time, no further changes can be made.

    Parameters
    ----------
    class_id: int
        the classification's identifier

    Returns
    -------
    boolean. False if the time is exceeded, True otherwise.

    """
    try:
        sql="""
            SELECT
                class_datetime
            FROM
                lt_classif
            WHERE
                class_id = %s;
            """
        output = db_connect(sql, (class_id, ), output=True)
        delta = dt.datetime.now() - output[0][0]
        return delta > dt.timedelta(minutes=2) 
    except Exception as error:
        logging.error(f'IN report_time_limit: {error}')  

def class_decrypt(class_id):
    """
    Change the type_id of a classification
    to the full name and the bin image

    Parameters
    ----------
    class_id: int
        the classification's identifier

    Returns
    -------
    Dict object with type_name (str) and binary image (base64)
    """
    try:
        sql = """SELECT type_name, type_img
                FROM lt_type
                WHERE type_id = %s;"""
        return db_connect(sql, (class_id,), output=True)[0]
    except Exception as error:
        logging.error(f'IN class_decrypt: {error}')  

def add_classif(classif, user_id=None):
    """
    Add a new classification in LT_CLASSIF table
    with a type identifier and a score
    return the classif identifier

    Parameters
    ----------
    classif: tuple
        tuple with the type_id and de classification's score
    user_id: int (optional)
        the user's identifier

    Returns
    -------
    integer: the classification identifier
    """
    logging.info('EXE add_classif')
    try:
        sql = """INSERT INTO lt_classif(user_id, type_id, class_score, class_datetime, class_ok)
                VALUES(%s, %s, %s, NOW(), TRUE) RETURNING class_id;"""
        var = [user_id] + list(classif)
        tab = db_connect(sql, var, output=True)
        return tab[0][0]
    except Exception as error:
        logging.error(f'IN add_classif: {error}')  

def delete_hist(user_id):
    """
    Delete all classification history of a user.
    Delete all classification from the user dans all messages.

    Parameters
    ----------
    user_id: str
        a user's identifier

    Returns
    -------
    Nothing
    """
    logging.info("EXE delete_hist for a user")
    try : 
        sql="""
            DELETE FROM lt_classif
            WHERE user_id = %s;
            DELETE FROM lt_message
            WHERE user_id = %s;
            """
        db_connect(sql, (user_id,), output=False)
    except Exception as error : 
        logging.error(f'IN delete_hist: {error}')

def delete_user(user_id):
    """
    Delete a user from the LT_USER table.
        - User classifications in LT_CLASSIF are anonymised
        - User messages in LT_MESSAGE are deleted

    Parameters
    ----------
    user_id: str
        a user's identifier

    Returns
    -------
    Nothing
    """
    logging.info("EXE delete_user for a user")
    try : 
        sql="""
            DELETE FROM lt_user
            WHERE user_id = %s;
            """
        db_connect(sql, (user_id,), output=False)
    except Exception as error : 
        logging.error(f'IN delete_user: {error}')

def is_sub(email):
    """
    Check is a user has subscribed to the Newsletter

    Parameters
    ----------
    email: str
        a user's email address

    Returns
    -------
    Booleen: True if the user has subscribed, False otherwise
    """
    try:
        sql="""
            SELECT
                sub_mail
            FROM
                lt_subscribe
            WHERE
                sub_mail = %s;
            """
        return not not db_connect(sql, (email,), output=True)
    except Exception as error : 
        logging.error(f'IN is_sub: {error}')   
    
# model
model = tf.keras.models.load_model('./api/prod_model.h5')

def ml_get_class(data):
    """
    Classify a image into 7 differents clategories
    with the deep learning model

    Parameters
    ----------
    data: image
        a valide image

    Returns
    -------
    Tuple with the type identifier and the classif score
    """
    logging.info("EXE ml_get_class")
    try:
        with tempfile.NamedTemporaryFile() as image:
            image.write(data)
            img = tf.keras.utils.load_img(image.name, target_size=(224, 224))
        img = tf.keras.utils.img_to_array(img)
        img = np.expand_dims(img, axis=0)
        img = tf.keras.applications.vgg16.preprocess_input(img)
        score = model.predict(img)
        return int(np.argmax(score)), round(float(np.max(score)) * 100, 2)
    except Exception as error : 
        logging.error(f'IN ml_get_class: {error}')


# ====================== #
# === AUTHENTICATION === # 
# ====================== #

def admin_required():
    """
    Create a decorator to check if the token in the query
    contains the booleen admin on True
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["admin"]:
                return fn(*args, **kwargs)
            else:
                return jsonify(status='fail', msg="Admins Only"), 403
        return decorator
    return wrapper

def revoke_token(jti_token):
    """
    Add the jti's token in LT_BLOCKLIST table

    Parameters
    ----------
    jti_token: str
        the token's id extract with get_jwt()['jti']

    Returns
    -------
    None
    """
    try:
        sql="""INSERT INTO lt_blocklist(block_token, block_datetime)
            VALUES(%s, NOW());"""
        db_connect(sql, (jti_token,), output=False)
    except Exception as error : 
        logging.error(f'IN revoke_token: {error}')

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict) -> bool:
    """
    Add the jti's token in LT_BLOCKLIST table

    Parameters
    ----------
    jti_token: str
        the token's id extract with get_jwt()['jti']

    Returns
    -------
    Boolean. True if the token blocklisted, False otherwise.
    """
    try:
        sql="""
            SELECT 
                block_id
            FROM 
                lt_blocklist
            WHERE
                block_token = %s
            """
        jti = jwt_payload["jti"]
        token = not db_connect(sql, (jti,), output=True)
        return not token
    except Exception as error : 
        logging.error(f'IN check_if_token_is_revoked: {error}')    

@app.route('/v1/register', methods=['POST'])
def register():
    """
    Register a new user with his name, email address and password

    Parameters
    ----------
    the request's payload must contain :
        - valid email address: str
        - name: str
        - valid password (8 char, 1 capital letter, 1 number, 1 special char): str

    Returns
    -------
    JSON object with the request status : success or fail 
    """
    logging.info("EXE register")
    try:
        auth = request.form
        if not auth or not auth.get('email') or not auth.get('password') or not auth.get('name'):
            return jsonify(status='fail', msg='Form with Email, Name and Password is Required'), 400

        email = request.form['email']
        if existe := email_check(email):
            return jsonify(status='fail', msg='User already exists. Try logging in'), 409

        if not email_valid(email):
            return jsonify(status='fail', msg='Invalid Email'), 401

        if not pwd_valid(request.form['password']):
            return jsonify(
                status='fail', 
                msg='Invalid Password (Minimum 8 characters and at least 1 Upper Case alphabet, 1 number, 1 special character)'), 401

        pwd_hash = bcrypt.generate_password_hash(request.form['password']).decode()
        logging.info("! new user added")
        add_user(email=email, name=request.form['name'], password=pwd_hash, admin=email == 'kohler.mick@gmail.com') # ajout de l'admin
        return jsonify(status='success', msg='User Created Successfully'), 201
    except Exception as error : 
        logging.error(f'IN register() endpoint: {error}')    

@app.route('/v1/login', methods=['GET'])
def login():
    """
    Compare user password with the one stored in database.
    The password is hashed, bcrypt checks the match

    Parameters
    ----------
    the request's payload must :
        - email: str
        - password: str

    Returns
    -------
    JSON Object with the user name, email, register date, admin bool 
    and token identification 
    """
    logging.info("EXE login")
    try:
        auth = request.form
        if not auth or not auth.get('email') or not auth.get('password'):
            return jsonify(status='fail', msg='Login Required (email and password)'), 400
        email = request.form['email']
        password = request.form['password']
        if email_test := email_check(email):
            if user_info := check_user(email, password):
                logging.info("! New user logged")
                access_token = create_access_token(
                    identity=email, 
                    additional_claims={'user_id': user_info[0] , 'admin': user_info[3]})
                return jsonify(
                    status='success',
                    msg='Login Successful', 
                    data={'name': user_info[1],
                        'email': email, 
                        'admin': user_info[3],
                        'time':user_info[2],
                        'access_token': access_token}), 200
            return jsonify(status='fail', msg='Wrong Password'), 400
        return jsonify(status='fail', msg='User does not exist'), 400 
    except Exception as error : 
        logging.error(f'IN login() endpoint: {error}')      

@app.route('/v1/password/forgot', methods=["GET"])
def forgot_password():
    """
    Send an email to change the user account password 
    when the user has forgotten it.

    Parameters
    ----------
    the request's payload must contain a valid email address

    Returns
    -------
    JSON file and an email is sent to the email address. 
    """
    logging.info("EXE forgot_password")
    try:
        auth = request.form
        if not auth or not auth.get('email'):
            return jsonify(status='fail', msg='Email Required'), 400
        email = request.form['email']
        if email_test := email_check(email):
            logging.info("! email send")
            reset_token = create_access_token(
                identity=email, 
                additional_claims={'user_id': email_test[0][0], 'recup':True}, 
                expires_delta=dt.timedelta(minutes=5))
            body = f"""
                <p>Dear User</p>
                <p>
                    To reset your password
                    <a href="http://litter-tracker.eu/v1/password/reset?jwt={reset_token}">click here</a>.
                </p>
                <p>If you have not requested a password reset simply ignore this message.</p>
                <p>Sincerely</p>
                <p>LITTER Tracker Support Team</p>
                    """
            msg = Message(
                subject='LITTER Tracker - Reset Password',
                html=body,
                recipients=[email]
            )
            mail.send(msg)
            return jsonify(status='success', msg='Email send'), 200
        return jsonify(status='fail', msg='User does not exist'), 400 
    except Exception as error : 
        logging.error(f'IN forgot_password() endpoint: {error}')    

@app.route('/v1/password/reset', methods=["GET", "POST"])
@jwt_required(locations=["headers", "query_string", "json"])
def reset_password():
    """
    When the request method is GET, display a form to put a new password.
    When the user clicks on submit, a POST request is send and the fonction 
    checks if the password is valid. The password is hashed and saved in this case.  

    Parameters
    ----------
    the request's payload must contain a special Token for 
    password reset process. 

    Returns
    -------
    With de GET method, display a HTML form. With the POST method, nothing.
    """
    # PUT
    if request.method == 'POST':
        auth = request.form
        div = """
                <div style="text-align:center; font-family: Nunito, Roboto, Noto, Arial, sans-serif">
                    <h2 style="color:#14d35b">L.I.T.T.E.R. Tracker</h1>
                    <h3>Reset Password</h3><br><br>
                    <h3 style="color:{}">{}</h3>
                </div>
               """
        if auth['pwd'] != auth['cpwd']:
            msg = "Passwords do not match."
            return div.format('#FF8552', msg)
        if not pwd_valid(auth['pwd']):
            msg = 'Invalid Password (Minimum 8 characters and at least 1 Upper Case alphabet, 1 number, 1 special character)'
            return div.format('#FF8552', msg)
        user_id = get_jwt()['user_id']
        pwd_hash = bcrypt.generate_password_hash(auth['pwd']).decode()
        change_pwd(user_id, pwd_hash)
        msg = "Your password has been successfully changed"
        return div.format('#14d35b', msg)
    # GET
    token = request.args['jwt']
    return  f"""
            <form method="POST" style="display: block; width: 500px; margin: 60px auto; 
                text-align: left; font-family: Nunito, Roboto, Noto, Arial, sans-serif">
                <h2 style="color: #14d35b; text-align: center">L.I.T.T.E.R. Tracker</h1><br>
                <h3>Reset Password</h3>
                <label for="pwd" style="color: #757575">New Password :</label>
                <input type="password" placeholder="password" id="pwd" name="pwd" 
                       style="width: 100%; height: 40px; box-sizing: border-box; display: inline-block; 
                       border-radius: 5px; padding: 0 15px; margin: 10px 0; border: 3px solid #2F96EF"><br><br>
                <label for="cpwd" style="color: #757575">Confirm Password :</label>
                <input type="password" placeholder="confirm password" id="cpwd" name="cpwd"
                       style="width: 100%; height: 40px; box-sizing: border-box; display: inline-block; 
                       border-radius: 5px; padding: 0 15px; margin: 10px 0; border: 3px solid #2F96EF">
                <input type="hidden" id="jwt" name="jwt" value={token}><br><br>
                <div align=center> <input 
                    type="submit" value="Submit"
                    style="font-weight: 500;
                        padding: 0.35em 1.2em;
                        border: 0.1em solid;
                        margin: 0 0.3em 0.3em 0;
                        display: inline-block;
                        font-size: 14px;
                        font-weight: 700;
                        border-radius: 0.12em;
                        box-sizing: border-box;
                        text-transform: uppercase;
                        color: white;
                        background-color: #14d35b";></div>
            </form>
            """


# ================ #
# === OPEN API === # 
# ================ #

@app.route('/v1/img_classif', methods=['GET'])
def image_classification():
    """
    Indicate the type of waste in an image

    Parameters
    ----------
    the request's body must contain a valid image
    *.png or *.jpeg image is recommended

    Returns
    -------
    JSON Object with :
        - class_id: int
        - label: str
        - score: float
        - image: binary image
    """
    try:
        user_id = get_jwt()['user_id'] if verify_jwt_in_request(optional=True) else None
        if not request.data:
            return jsonify(status='fail', msg='Missing Image File'), 400
        if imghdr.what(None, h=request.data) is None:
            return jsonify(status='fail', msg='Cannot Identify Image File'), 500
        else:
            data = request.data
            
        # image classification
        classif = ml_get_class(data)
        class_id = add_classif(classif, user_id)
        label, bin_img = class_decrypt(classif[0])

        # return
        base64_img = base64.b64encode(bin_img)
        image = base64_img.decode('utf-8')
        return jsonify(status='success', 
            msg='Type of waste',
            data={
            'class_id':class_id, 
            'label':label, 
            'score':classif[1], 
            'image':image}), 200
    except Exception as error : 
        logging.error(f'IN image_classification() endpoint: {error}')    

@app.route('/v1/img_classif/wrong', methods=['POST'])
def report_wrong_class():
    """
    Report the wrong classification of an image.
    If the parameter save_img is True, the image is saved in LT_REPORT,
    otherwise only the status in LT_CLASSIF is changed.

    Parameters
    ----------
    the request's body must contain:
        - a valid image: *.png or *.jpeg image is recommended
    in the string query: 
        - class_id: int
        - save_img: bool

    Returns
    -------
    JSON Object with the status: success or fail.
    """
    logging.info("EXE report_wrong_class")
    try:
        save_img = request.args.get('save_img') == 'True'
        try:
            class_id = request.args['class_id']
        except Exception:
            return jsonify(status='fail', msg="Parameter 'class_id' is Required"), 400
        if not request.data:
            return jsonify(status='fail', msg='Missing image file'), 400
        if imghdr.what(None, h=request.data) is None:
            return jsonify(status='fail', msg='Cannot Identify Image File'), 500
        else:
            data = request.data

        if report_time_limit(class_id):
            return jsonify(status='fail', msg='Time Exceeded to Modifiy Classficiation Status (2 minutes max)'), 403

        if save_img:
            sql = """INSERT INTO lt_report(class_id, report_img, report_ok)
                    VALUES(%s, %s, FALSE);"""
            db_connect(sql, (class_id, data), output=False)
        sql = """UPDATE lt_classif
                SET class_ok = FALSE
                WHERE class_id = %s;"""
        db_connect(sql, (class_id, ), output=False)
        return jsonify(status='success', msg='Wrong Classification Saved'), 201
    except Exception as error: 
        logging.error(f'IN report_wrong_class() endpoint: {error}')    


# ================ #
# === USER API === #
# ================ #

@app.route('/v1/user/history', methods=['GET'])
@jwt_required()
def user_history():
    """
    Aggregate all classifications made by the user for each class

    Parameters
    ----------
    The request header must contain the User Token

    Returns
    -------
    JSON Object with all data. Each key is a class
    """
    try:
        sql = """
            SELECT 
                t.type_name,
                count(p.class_id) AS nb_pred
            FROM
                lt_classif p
                LEFT JOIN lt_type t ON p.type_id = t.type_id
            WHERE
                p.user_id = %s
                AND p.class_ok = True
            GROUP BY
                t.type_name;
            """
        user_id = get_jwt()['user_id']
        output = db_connect(sql, (user_id,), output=True)
        df = pd.DataFrame(output, columns=['type', 'nb'])
        df['%nb'] = round((df['nb']/df['nb'].sum())*100, 2)
        df['%nb'] = df['%nb'].apply(lambda x: f"{str(x)} %")
        df.sort_values('nb', ascending=False, inplace=True)
        return jsonify(status='success', msg=f'User (id.{user_id}) History', data=df.to_dict('records')), 200
    except Exception as error: 
        logging.error(f'IN user_history() endpoint: {error}')   

@app.route('/v1/user/change/password', methods=['PUT'])
@jwt_required()
def user_change_password():
    """
    Change the user password if he knows his old password

    Parameters
    ----------
    The request header must contain the User Token
    The payload must contain : 
        - old_password: str
        - new_password: str

    Returns
    -------
    JSON Object with the status: success or fail
    """
    try:
        auth = request.form
        if not auth or not auth.get('old_password') or not auth.get('new_password'):
            return jsonify(status='fail', msg='Form with Old Password and New Password is Required'), 400

        email = get_jwt_identity()
        user_id = get_jwt()['user_id']
        if user_info := check_user(email, auth['old_password']):
            if pwd_valid(auth['new_password']):
                pwd_hash = bcrypt.generate_password_hash(auth['new_password']).decode()
                change_pwd(user_id, pwd_hash)
                return jsonify(status='success', msg='Password Changed'), 200
            return jsonify(
                status='fail', 
                msg='Invalid Password (Minimum 8 characters and at least 1 Upper Case alphabet, 1 number, 1 special character)'), 401
        return jsonify(status='fail', msg='Wrong Password'), 400 
    except Exception as error: 
        logging.error(f'IN user_change_password() endpoint: {error}')   

@app.route('/v1/user/change/email', methods=['PUT']) 
@jwt_required()
def user_change_email():
    """
    Change the user email address

    Parameters
    ----------
    The request header must contain the User Token
    The payload must contain : 
        - email: str

    Returns
    -------
    JSON Object with the status: success or fail
    """
    try:
        user_id = get_jwt()['user_id']
        auth = request.form
        if not auth or not auth.get('email'):
            return jsonify(status='fail', msg='Form with a New Email is Required'), 400
        new_email = request.form['email']
        if existe := email_check(new_email):
            return jsonify(status='fail', msg='User already exists. Try logging in'), 409
        if not email_valid(new_email):
            return jsonify(status='fail', msg='Invalid Email'), 401
        change_email(user_id, new_email)
        claims = get_jwt()
        token = create_access_token(identity=new_email, additional_claims={'user_id': claims['user_id'] , 'admin': claims['admin']})
        revoke_token(claims["jti"])
        return jsonify(status='success', msg='Email Changed. Previous Token Revoked', new_token=token), 200
    except Exception as error: 
        logging.error(f'IN user_change_email() endpoint: {error}')   

@app.route('/v1/user/change/name', methods=['PUT']) 
@jwt_required()
def user_change_name():
    """
    Change the user email name

    Parameters
    ----------
    The request header must contain the User Token
    The payload must contain : 
        - name: str

    Returns
    -------
    JSON Object with the status: success or fail
    """
    try:
        user_id = get_jwt()['user_id']
        auth = request.form
        if not auth or not auth.get('name'):
            return jsonify(status='fail', msg='Form with a New Name is Required'), 400
        change_name(user_id, auth['name'])
        return jsonify(status='success', msg='Name Changed'), 200
    except Exception as error: 
        logging.error(f'IN user_change_email() endpoint: {error}')   

@app.route('/v1/user/delete/history', methods=['DELETE'])
@jwt_required()
def user_delete_history():
    """
    Delete the User history

    Parameters
    ----------
    The request header must contain the User Token

    Returns
    -------
    JSON Object with the status: success or fail
    """
    try:
        user_id = get_jwt()['user_id']
        delete_hist(user_id)
        return jsonify(status='success', msg='History Deleted'), 200
    except Exception as error: 
        logging.error(f'IN user_delete_history() endpoint: {error}')  

@app.route('/v1/user/delete/account', methods=['DELETE'])
@jwt_required()
def user_delete_account():
    """
    Delete the User Account

    Parameters
    ----------
    The request header must contain the User Token

    Returns
    -------
    JSON Object with the status: success or fail
    """
    try:
        user_id = get_jwt()['user_id']
        delete_user(user_id)
        revoke_token(get_jwt()["jti"])
        return jsonify(status='success', msg='User Deleted'), 200
    except Exception as error: 
        logging.error(f'IN user_delete_account() endpoint: {error}')  

@app.route('/v1/user/subscription', methods=['GET'])
@jwt_required()
def subscription_state():
    """
    Check the status of the user subscription to the Newsletter

    Parameters
    ----------
    The request header must contain the User Token

    Returns
    -------
    JSON Object with the status of the subscription
    """
    try:
        email = get_jwt_identity()
        if is_sub(email):
            return jsonify(status='success', msg='User has subscribed'), 200
        else:
            return jsonify(status='success', msg='User has not subscribed'), 200
    except Exception as error: 
        logging.error(f'IN subscription_state() endpoint: {error}')  


# ================= #
# === ADMIN API === #
# ================= #

@app.route('/', methods=['GET'])
def check_api():
    """
    Check if the API is available

    Returns
    -------
    JSON Object is the API is on
    """
    return jsonify(status= 'success', msg='Welcome to the L.I.T.T.E.R. TRACKER API'), 418

@app.route('/v1/admin/year_hist', methods=['GET'])
@admin_required()
def year_hist():
    """
    Return all classifications from all users in a year-over-year

    Parameters
    ----------
    The request header must contain the Admin Token

    Returns
    -------
    JSON Object with each month in key
    """
    try:
        sql="""
            SELECT
                COUNT(class_id) AS nb_pred,
                TO_CHAR(class_datetime, 'YYYY/MM') AS date
            FROM
                lt_classif
            GROUP BY
                TO_CHAR(class_datetime, 'YYYY/MM')
            ORDER BY 
                date ASC
            LIMIT 12
            """
        output = db_connect(sql, output=True)
        if len(output) < 12:
            last_date = sorted([el[1] for el in output])[0]
            for i in range(12-len(output)):
                month_before = dt.datetime.strptime(last_date, '%Y/%m') + relativedelta(months=-(1+i))
                output.insert(0, (0, month_before.strftime('%Y/%m')))
        return jsonify(status='success', msg='year history', data=output), 200
    except Exception as error: 
        logging.error(f'IN year_hist() endpoint: {error}')   

@app.route('/v1/admin/report', methods=['GET'])
@admin_required()
def report_hist():
    """
    Return all wrong classifications from all users
    limit the number of images in the JSON with the parameter limit

    Parameters
    ----------
    The request header must contain the Admin Token
    (optional) The string query contain the parameter limit:int

    Returns
    -------
    JSON Object. For each image: 
        - class_id: int
        - score: float
        - binary image: str
    """
    try:
        # optional parameter : limit
        try:
            nb_img = int(request.args.get('limit')) if request.args.get('limit') is not None else 100
        except Exception:
            return jsonify(status='fail', msg="Parameter 'nb_img' must be an Integer"), 400

        sql="""
            SELECT 
                r.class_id,
                type_name AS wrong_pred,
                class_score AS score,
                report_img
            FROM
                lt_report r
                LEFT JOIN lt_classif p ON r.class_id = p.class_id
                LEFT JOIN lt_type t ON t.type_id = p.type_id
            WHERE
                report_ok IS NOT TRUE
            ORDER BY 
                p.class_datetime DESC 
            LIMIT %s;
            """
        output = db_connect(sql, (nb_img,), output=True) 
        data = []
        for i in range(nb_img):
            with contextlib.suppress(Exception):
                item = {}
                item['class_id'], item['label'], score, image = output[i]
                item['score'] = float(score)
                base64_img = base64.b64encode(image)
                item['img'] = base64_img.decode('utf-8')
                data.append(item)
        return jsonify(status='success', msg='wrong predictions history', limit=nb_img, data=data), 200
    except Exception as error: 
        logging.error(f'IN report_hist() endpoint: {error}')   

@app.route('/v1/admin/report', methods=['PUT'])
@admin_required()
def check_report():
    """
    Valid a wrong classification. It will be ready for improve the model.

    Parameters
    ----------
    The request header must contain the Admin Token
    The string query contain the parameter class_id:int

    Returns
    -------
    JSON Object with the request status: success or fail
    """
    try:
        try:
            class_id = request.args['class_id']
            if classid_unknown(class_id):
                return jsonify(status='fail', msg="class_id is unknown"), 400 
        except Exception:
            return jsonify(status='fail', msg="Parameter 'class_id' is Required"), 400
            
        sql="""
            UPDATE lt_classif
            SET class_ok = TRUE
            WHERE class_id = %s;
            DELETE FROM lt_report
            WHERE class_id = %s;
            """
        db_connect(sql, (class_id, class_id,), output=False)
        return jsonify(status='success', msg='Report Status Changed'), 200
    except Exception as error: 
        logging.error(f'IN check_report() endpoint: {error}')  

@app.route('/v1/admin/report', methods=['DELETE'])
@admin_required()
def del_report():
    """
    Delete a wrong classification if the picture isn't relevant

    Parameters
    ----------
    The request header must contain the Admin Token
    The string query contain the parameter class_id:int

    Returns
    -------
    JSON Object with the request status: success or fail
    """
    try:
        try:
            class_id = request.args['class_id']
            if classid_unknown(class_id):
                return jsonify(status='fail', msg="class_id is unknown"), 400 
        except Exception:
            return jsonify(status='fail', msg="Parameter 'class_id' is Required"), 400

        sql="""
            DELETE FROM lt_report
            WHERE class_id = %s;
            """
        db_connect(sql, (class_id,), output=False)
        return jsonify(status='success', msg='Report Deleted'), 200
    except Exception as error: 
        logging.error(f'IN del_report() endpoint: {error}')  

@app.route('/v1/admin/message', methods=['GET'])
@admin_required()
def message_hist():
    """
    Return all messages from users

    Parameters
    ----------
    The request header must contain the Admin Token
    (optional) The string query contain the parameters:
        - limit:int
        - all:bool

    Returns
    -------
    JSON Object. For each message:
        - msg_id: int
        - name': str
        - mail: str
        - message: str
        - register: booleen
        - date: datatime
    """
    try:
        # optional parameter : limit
        try:
            nb_messages = int(request.args.get('limit')) if request.args.get('limit') is not None else 100
        except Exception:
            return jsonify(status='fail', msg="Parameter 'limit' must be an Integer"), 400
        # optional parameter : all 
        if request.args.get('all') is None:
            all_msg = False
        elif request.args.get('all') not in ['True', 'False']:
            return jsonify(status='fail', msg="Parameter 'all' is a Boolean. Please choose True or False"), 400
        all_msg = request.args.get('all') == 'True'

        sql_header="""
            SELECT
                msg_id,
                CASE
                    WHEN user_id IS NOT NULL THEN TRUE
                    ELSE FALSE
                END AS register,
                msg_name AS name,
                msg_mail AS mail,
                msg_txt AS message,
                TO_CHAR(msg_datetime, 'DD/MM/YYYY') AS date
            FROM
                lt_message"""
        sql_footer="""
            ORDER BY 
                msg_datetime DESC 
            LIMIT %s;
            """
        if all_msg:
            sql = sql_header + sql_footer
        else:
            sql_where="""
            WHERE 
                msg_read IS NOT TRUE
            """
            sql= sql_header + sql_where + sql_footer
        output = db_connect(sql, (nb_messages,), output=True)
        data = []
        for message in output:
            item = {
                'msg_id': message[0],
                'name': message[2],
                'mail': message[3],
                'message': message[4],
                'register': message[1],
                'date': message[5],
            }
            data.append(item)
        return jsonify(status='success', msg="Users' Messages History", limit=nb_messages, data=data), 200
    except Exception as error: 
        logging.error(f'IN message_hist() endpoint: {error}')  

@app.route('/v1/admin/message', methods=['DELETE'])
@admin_required()
def del_message():
    """
    Delete a user message

    Parameters
    ----------
    The request header must contain the Admin Token
    The request parameter must contain msg_id:int

    Returns
    -------
    JSON Object with the request status: success or fail
    """
    try:
        try:
            msg_id = request.args['msg_id']
            if msgid_unknown(msg_id):
                return jsonify(status='fail', msg="msg_id is unknown"), 400 
        except Exception:
            return jsonify(status='fail', msg="Parameter 'msg_id' is Required"), 400

        sql="""
            DELETE FROM lt_message
            WHERE msg_id = %s;
            """
        db_connect(sql, (msg_id,), output=False)
        return jsonify(status='success', msg='Message Deleted'), 200
    except Exception as error: 
        logging.error(f'IN del_message() endpoint: {error}') 

@app.route('/v1/admin/message', methods=['PUT'])
@admin_required()
def check_message():
    """
    Sets the state of MSG_READ to TRUE for a message in the LT_MESSAGE table

    Parameters
    ----------
    The request header must contain the Admin Token
    The request parameter must contain msg_id:int

    Returns
    -------
    JSON Object with the request status: success or fail
    """
    try:
        try:
            msg_id = request.args['msg_id']
            if msgid_unknown(msg_id):
                return jsonify(status='fail', msg="msg_id is unknown"), 400 
        except Exception:
            return jsonify(status='fail', msg="Parameter 'msg_id' is Required"), 400

        sql="""
            UPDATE lt_message
            SET msg_read = TRUE
            WHERE msg_id = %s;
            """
        db_connect(sql, (msg_id,), output=False)
        return jsonify(status='success', msg='Message Read'), 200
    except Exception as error: 
        logging.error(f'IN check_message() endpoint: {error}') 


# =============== #
# === CONTACT === #
# =============== #

@app.route('/v1/message', methods=['POST'])
def add_message():
    """
    Add a message in the LT_MESSAGE

    Parameters
    ----------
    The request payload must contain:
        - name: str
        - email: str
        - text: str
    (optional) the header request can be contain a User Token

    Returns
    -------
    JSON Object with the request status: success or fail
    """
    try:
        verify_jwt_in_request(optional=True)
        try:
            user_id = get_jwt()['user_id']
        except Exception:
            user_id = None
        data = request.form
        if not data or not data.get('name') or not data.get('email') or not data.get('text'):
            return jsonify(status='fail', msg='Message Required (name, email, and text)'), 400
        if email_test := email_valid(data['email']):
            sql="""
                INSERT INTO lt_message(user_id, msg_name, msg_mail, msg_txt, msg_datetime, msg_read)
                VALUES(%s, %s, %s, %s, NOW(), FALSE);
                """
            db_connect(sql, (user_id, data['name'], data['email'], data['text']), output=False)
            return jsonify(status='success', msg='Message Saved'), 201
        return jsonify(status='fail', msg='Invalid email'), 400 
    except Exception as error: 
        logging.error(f'IN add_message() endpoint: {error}') 

@app.route('/v1/subscribe', methods=['POST'])
def add_subscription():
    """
    Add an email to the LT_SUBSCRIPTION table of the databse

    Parameters
    ----------
    the request's payload must contain a valid email address

    Returns
    -------
    JSON Object with the request status: success or fail
    """
    try:
        try:
            mail = request.form['email']
            if not email_valid(mail):
                return jsonify(status='fail', msg="Invalid email"), 400 
        except Exception:
            return jsonify(status='fail', msg="Parameter 'email' is Required"), 400

        sql="""
            INSERT INTO lt_subscribe(sub_mail, sub_datetime)
            VALUES(%s, NOW());
            """
        try:
            db_connect(sql, (mail, ), output=False)
            return jsonify(status='success', msg='subscribed'), 201
        except Exception:
            return jsonify(status='fail', msg='already subscribed'), 403
    except Exception as error: 
        logging.error(f'IN add_subscription() endpoint: {error}') 

@app.route('/v1/subscribe', methods=['DELETE'])
def del_subscription():
    """
    Delete an email to the LT_SUBSCRIPTION table of the databse

    Parameters
    ----------
    the request's payload must contain a valid email address

    Returns
    -------
    JSON Object with the request status: success or fail
    """
    try:
        try:
            mail = request.form['email']
            if not email_valid(mail):
                return jsonify(status='fail', msg="Invalid email"), 400 
        except Exception:
            return jsonify(status='fail', msg="Parameter 'email' is Required"), 400

        sql="""
            DELETE FROM lt_subscribe
            WHERE sub_mail = %s
            RETURNING sub_mail;
            """
        if output := db_connect(sql, (mail,), output=True):
            return jsonify(status='success', msg='unsubscribed'), 200
        else:
            return jsonify(status='fail', msg='No subscription found'), 404
    except Exception as error: 
        logging.error(f'IN del_subscription() endpoint: {error}') 


# ============ #
# === MAIN === #
# ============ #

if __name__ == "__main__":
    launch_time = pytz.timezone('Europe/Paris').localize(dt.datetime.now()).strftime('%Y-%m-%d_%H_%M')
    logging.basicConfig(filename=f"./api/logs/outlogs_{launch_time}.log",level=logging.INFO)
    serve(app, host="0.0.0.0", port=8080)