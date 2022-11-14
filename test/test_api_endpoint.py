import json
import psycopg2
import pytest
from api import litrack_api as lta


# ====================== #
# === INITIALIZATION === # 
# ====================== #

def db_connect(sql_querie, variable=(None, ), output=True):
    """
    Create a connection to the test database.
    Override the api db_connect fonction 

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
    conn = psycopg2.connect(host="localhost", port=5432, database="test_litrack")
    cur = conn.cursor()
    cur.execute(sql_querie, variable)
    tab = cur.fetchall() if output else None
    conn.commit()
    cur.close(); conn.close()
    return tab

# override db_connect to use test database
lta.db_connect = db_connect

@pytest.fixture
def client():
    """REST API client"""
    app = lta.app
    app.config.update({
        "TESTING": True,
        "JWT_SECRET_KEY": 'super-secret',
    })
    with app.test_client() as client:
        yield client

@pytest.fixture
def admin_login(client):
    """Creation of a Admin Token"""
    payload = {'email':'admin.test@address.com', 'password':'Admin!1337'}
    response = client.get("/v1/login", data=payload)
    data = json.loads(response.data.decode())
    return data['data']['access_token']


# ====================== #
# === AUTHENTICATION === # 
# ====================== #

"""
def test_register(client):
    payload = {
        'email':'admin.test@address.com', 
        'name':'admin', 
        'password':'Admin!1337'}
    response = client.post("/v1/register", data=payload)
    assert response.status_code == 201
"""


# ================= #
# === ADMIN API === #
# ================= #

def test_check_api(client):
    """Test the check_api endpoint"""
    response = client.get("/")
    print(response.data)
    assert response.status_code == 418

def test_message_hist(client, admin_login):
    """
    Test if the Admin can read all messages
    Second Part of a User Story : Send, read and delate a message
    """
    # right access to the data
    headers = {'Authorization': f'Bearer {admin_login}'}
    response = client.get("/v1/admin/message?limit=10", headers=headers)
    data = json.loads(response.data.decode())
    assert response.status_code == 200
    assert len(data['data']) < 11

    # send wrong all parameter
    response = client.get("/v1/admin/message?all=test", headers=headers)
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert "Parameter 'all' is a Boolean. Please choose True or False" in data['msg']

    # send wrong limit parameter
    response = client.get("/v1/admin/message?limit=test", headers=headers)
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert "Parameter 'limit' must be an Integer" in data['msg']


# =============== #
# === CONTACT === #
# =============== #

def test_add_message(client):
    """
    Test if a User can add a message
    First Part of a User Story : Send, read and delate a message
    """
    # right access to the data
    payload = {
        'email':'msg.test@address.com', 
        'name':'add_test', 
        'text':'testing'}
    response = client.post("/v1/message", data=payload)
    assert response.status_code == 201

    # send bad email
    payload = {
        'email':'test', 
        'name':'add_test', 
        'text':'testing'}
    response = client.post("/v1/message", data=payload)
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert 'Invalid email' in data['msg']

    # send no data
    response = client.post("/v1/message")
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert 'Message Required (name, email, and text)' in data['msg']

def test_del_message(client, admin_login):
    """
    Test if the Admin can delete a message
    Third Part of a User Story : Send, read and delate a message
    """
    # right access to the data
    msg_id = db_connect("SELECT msg_id FROM lt_message ORDER BY msg_datetime DESC LIMIT 1")[0][0]
    headers = {'Authorization': f'Bearer {admin_login}'}
    response = client.delete(f"/v1/admin/message?msg_id={msg_id}", headers=headers)
    assert response.status_code == 200

    # send invalid msg_id
    response = client.delete("/v1/admin/message?msg_id=2", headers=headers)
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert "msg_id is unknown" in data['msg']

    # send no data
    response = client.delete("/v1/admin/message", headers=headers)
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert "Parameter 'msg_id' is Required" in data['msg']

def test_add_subscription(client):
    """
    Test if an User can subscribe to the Newsletter
    First Part of a User Story : add and delete the Newsletter Subscription
    """
    # right access subscription endpoint
    payload = {'email':'sub.test@address.com'}
    response = client.post("/v1/subscribe", data=payload)
    assert response.status_code == 201

    # send same request
    response = client.post("/v1/subscribe", data=payload)
    assert response.status_code == 403

    # send bad email
    payload = {'email':'test'}
    response = client.post("/v1/subscribe", data=payload)
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert 'Invalid email' in data['msg']

    # send no data
    response = client.delete("/v1/subscribe")
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert "Parameter 'email' is Required" in data['msg']

def test_del_subscription(client):
    """
    Test if an User can unsubscribe to the Newsletter
    Second Part of a User Story : add and delete the Newsletter Subscription
    """
    # right access subscription endpoint
    payload = {'email':'sub.test@address.com'}
    response = client.delete("/v1/subscribe", data=payload)
    assert response.status_code == 200

    # send same request
    payload = {'email':'sub.test@address.com'}
    response = client.delete("/v1/subscribe", data=payload)
    assert response.status_code == 404

    # send bad email
    payload = {'email':'test'}
    response = client.delete("/v1/subscribe", data=payload)
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert 'Invalid email' in data['msg']

    # send no data
    response = client.delete("/v1/subscribe")
    data = json.loads(response.data.decode())
    assert response.status_code == 400
    assert "Parameter 'email' is Required" in data['msg']

def test_subscription_state(client, admin_login):
    """
    Test the check subscription endpoint
    Third Part of a User Story : add and delete the Newsletter Subscription
    """
    # right access subscription endpoint
    headers = {'Authorization': f'Bearer {admin_login}'}
    response = client.get("/v1/user/subscription", headers=headers)
    data = json.loads(response.data.decode())
    assert response.status_code == 200
    assert "User has subscribed" in data['msg']


# pytest to lunch all tests