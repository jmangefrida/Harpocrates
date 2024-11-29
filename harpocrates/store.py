"""
store.py

"""

import sqlite3


class Store(object):
    """docstring for Store"""
    
    def __init__(self, arg):
        super(Store, self).__init__()
        self.con = sqlite3.connect("store.db")
        self.cur = self.con.cursor()
        self.build_schema()

    def build_schema(self):
        
        self.cur.execute("CREATE TABLE IF NOT EXISTS user(" 
                         "username VARCHAR(32) PRIMARY KEY,"
                         " salt VARCHAR(32),"
                         " password VARCHAR(255)")
        self.cur.execute("CREATE TABLE IF NOT EXISTS setting("
                         "enc_key)")
        self.cur.execute("CREATE TABLE IF NOT EXISTS secret("
                         "name VARCHAR(32) PRIMARY KEY,"
                         " account_name VARCHAR(64),"
                         " secret,"
                         " description")
        self.cur.execute("CREATE TABLE IF NOT EXISTS role("
                         "name VARCHAR(64) PRIMARY KEY)")
        self.cur.execute("CREATE TABLE IF NOT EXISTS client("
                         "name VARCHAR(64) PRIMARY KEY,"
                         " ip_address VARCHAR(64),"
                         " role VARCHAR(64),"
                         " public_key VARCHAR(2048),"
                         " FOREIGN KEY (role) REFERENCES role (name))")
        self.cur.execute("CREATE TABLE IF NOT EXISTS role_assignment("
                         "id int PRIMARY KEY,"
                         " role_name VARCHAR(64),"
                         " secret_name VARCHAR(32),"
                         " FOREIGN KEY (role_name) REFERENCES role (name))"
                         " FOREIGN KEY (secret_name) REFERENCES secret (name))")
