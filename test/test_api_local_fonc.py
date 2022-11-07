import psycopg2
import unittest
from api import litrack_api as lta

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
        exemple: ['.jpg', '.png']
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

class TestUnitaires(unittest.TestCase):
    def test_email_valid(self):
        self.assertTrue(lta.email_valid(self.mail))
        self.assertFalse(lta.email_valid('Bonjour'))
        self.assertFalse(lta.email_valid('unit.test@gmail.com ; DROP TABLE'))

    def test_password(self):
        self.assertTrue(lta.pwd_valid(self.pwd))
        self.assertFalse(lta.pwd_valid('SuperPwd1234'))
        self.assertFalse(lta.pwd_valid('SuperPwd!'))
        self.assertFalse(lta.pwd_valid('superpwd!1234'))
        self.assertFalse(lta.pwd_valid('test'))

class TestLocalFonctions(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestLocalFonctions, self).__init__(*args, **kwargs)
        self.mail = 'test@address.com'
        self.name = 'test_user'
        self.pwd = 'SuperPwd!1234'
        self.admin = False
    
    def test_user_fonctions(self):
        #test add_user
        lta.add_user(self.mail, self.name, self.pwd, self.admin)

        user_id = db_connect("SELECT user_id FROM lt_user WHERE user_mail = 'test@address.com'")[0][0]
        user_name = db_connect(f"SELECT user_name FROM lt_user WHERE user_id = {user_id}")[0][0]
        user_admin = db_connect(f"SELECT user_admin FROM lt_user WHERE user_id = {user_id}")[0][0]
        user_pwd = db_connect(f"SELECT user_pwd FROM lt_user WHERE user_id = {user_id}")[0][0]
        self.assertEqual(user_name, self.name)
        self.assertFalse(user_admin)
        self.assertEqual(user_pwd, self.pwd)

        #test email_check
        self.assertEqual(lta.email_check('test@address.com')[0][0], user_id)
        self.assertListEqual(lta.email_check('unkown@address.com'), [])

        # test change pwd
        lta.change_pwd(user_id, 'SuperPwd1234')
        user_pwd = db_connect(f"SELECT user_pwd FROM lt_user WHERE user_id = {user_id}")[0][0]
        self.assertEqual(user_pwd, 'SuperPwd1234')
        self.assertNotEqual(user_pwd, self.pwd)
        lta.change_pwd(user_id, self.pwd)

        # test change mail 
        lta.change_email(user_id, 'fake@address.com')
        user_mail = db_connect(f"SELECT user_mail FROM lt_user WHERE user_id = {user_id}")[0][0]
        self.assertEqual(user_mail, 'fake@address.com')
        self.assertNotEqual(user_mail, self.mail)
        lta.change_pwd(user_id, self.mail)

        # test change name
        lta.change_name(user_id, 'new_name; DROP TABLE')
        user_name = db_connect(f"SELECT user_name FROM lt_user WHERE user_id = {user_id}")[0][0]
        self.assertEqual(user_name, 'new_name; DROP TABLE')
        self.assertNotEqual(user_pwd, self.name)
        lta.change_pwd(user_id, self.name)

        #test delete_user
        lta.delete_user(user_id)
        self.assertListEqual(db_connect(f"SELECT user_name FROM lt_user WHERE user_id = {user_id}"), [])

    def test_is_sub(self):
        self.assertTrue(lta.is_sub(self.mail))
        self.assertFalse(lta.is_sub('fake@address.com'))

    def test_class_decrypt(self):
        self.assertEqual(lta.class_decrypt(0)[0], 'cardboard')
        self.assertEqual(lta.class_decrypt(1)[0], 'e-waste')
        self.assertNotEqual(lta.class_decrypt(2)[0], 'medical')

    def test_add_classif(self):
        # ajout d'un élément
        # vérifier le time limite
        # vérifier si la classid_unknow
        pass

if __name__ == '__main__':
    # python -m unittest
    unittest.main()