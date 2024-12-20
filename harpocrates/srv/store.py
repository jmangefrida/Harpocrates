"""
store.py

"""

import sqlite3


class ItemExistsError(Exception):
    pass


class Store(object):
    """docstring for Store"""
    
    def __init__(self):
        super(Store, self).__init__()
        self.con = sqlite3.connect("store.db", check_same_thread=False)
        self.cur = self.con.cursor()
        self.build_schema()
        # print(self.cur.execute("select username from user where username = 'testadmin'", ()).fetchall())

    def build_schema(self):
        con = sqlite3.connect("store.db", check_same_thread=False)
        cur = self.con.cursor()
        
        self.cur.execute("""CREATE TABLE IF NOT EXISTS user(
                         username VARCHAR(32) PRIMARY KEY,
                         salt BLOB,
                         enc_key BLOB,
                         register_date DATETIME,
                         last_pass_change DATETIME,
                         account_type VARCHAR(32))""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS setting(
                         enc_key VARCHAR(255))""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS secret(
                         name VARCHAR(32) PRIMARY KEY,
                         account_name VARCHAR(64),
                         secret VARCHAR(255),
                         description VARCHAR(255))""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS role(
                         name VARCHAR(64) PRIMARY KEY,
                         description VARCHAR(64))""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS client(
                         name VARCHAR(64) PRIMARY KEY,
                         ip_address VARCHAR(64),
                         image_name VARCHAR(64),
                         public_key VARCHAR(2048),
                         FOREIGN KEY (image_name) REFERENCES image (name))""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS role_grant(
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         role_name VARCHAR(64),
                         secret_name VARCHAR(32),
                         FOREIGN KEY (role_name) REFERENCES role (name),
                         FOREIGN KEY (secret_name) REFERENCES secret (name))""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS image(
                         name VARCHAR(64) PRIMARY KEY,
                         date_registered TIMESTAMP,
                         registered_by VARCHAR(32),
                         role VARCHAR(64),
                         public_key VARCHAR(2048),
                         FOREIGN KEY (role) REFERENCES role (name))""")
        con.commit()

    def value_exists(self, table, field, value):
        query = "SELECT COUNT(*) FROM " + table + " WHERE " + field + " = ?"
        result = self.cur.execute(query, (value, )).fetchone()[0]
        if result == 0:
            return False
        else:
            return True

    def create(self, table, data):
        keys = list(data.keys())
        values = list(data.values())
        marks = ", ".join(['?'] * len(keys))
        keys = ", ".join(keys)

        query = "INSERT INTO {} ({}) VALUES ({})".format(table, keys, marks)
        print(query)
        print(values)
        self.cur.execute(query, values)
        #self.cur.execute('commit')
        self.con.commit()
        # r = self.cur.execute("select * from user", ()).fetchone()
        # print(r)
        return True

    def find(self, table, fields, filters):
        fields = ', '.join(fields)
        marks, filters = Store.encode_filters(filters)
        query = "SELECT {} from {} where {}".format(fields, table, marks)
        result = self.cur.execute(query, filters).fetchall()
        print(result)
        return result

    def read(self, table, fields, filters):
        fields = ', '.join(fields)
        marks, filters = Store.encode_filters(filters)
        query = "SELECT {} from {} where {}".format(fields, table, marks)
        query = "SELECT * from {} where {}".format(table, marks)
        # print(query)
        # print(filters)
        result = self.cur.execute(query, filters).fetchone()
        print('select')
        print(result)
        return result

    def update(self, table, values, filters):
        # fields = ', '.join(values)
        value_marks, enc_values = Store.encode_filters(values, True)
        filter_marks, filters = Store.encode_filters(filters)
        query = "UPDATE {} set {} WHERE {}".format(table, value_marks, filter_marks)
        print(enc_values)
        print(filters)
        enc_values.extend(filters)
        print(query)
        enc_values = tuple(enc_values)
        print(enc_values)
        self.cur.execute(query, enc_values)
        # self.cur.execute('update user set account_type = ? where username = ?', ('yello', 'testadmin'))
        # self.cur.execute('commit')
        self.con.commit()
        r = self.cur.execute('select * from user', ()).fetchall()
        print("updated")
        for row in r:
            print(row)
        #self.con.close()
        return True

    def delete(self, table, filters):
        marks, filters = Store.encode_filters(filters)
        query = "DELETE FROM {} WHERE {}".format(table, marks)
        self.cur.execute(query, filters)
        self.con.commit()
        return True

    @staticmethod
    def encode_fields(fields):
        return ", ".join(fields)

    @staticmethod
    def encode_filters(filters, update_select=False):
        """
        Convert multi-depth lists into sql format where caluse
        [{f1: v1, f2:v2},{f3: v3}] is (f1=v1 and f2=v2) or (f3=v3)
        {f1: v1, or:[{f2: v2}, {f3: v3}]} is f1=v1 and (f2=v2 or f3=v3)
        """
        columns = [x + ' = ?' for x in filters.keys()]
        if update_select is True:
            marks = ", ".join(columns)
        else:
            marks = " AND ".join(columns)
        values = list(filters.values())
        #marks = ' AND '.join(['? = ?'] * len(filters.keys()))
        encoded = []
        for key, value in filters.items():
            # encoded.append("{} = {}".format(key, value))
            encoded.extend([key, value])

        # print(encoded)
        # return marks, encoded
        return marks, values

    def new_user(self, username, salt, password):
        if self.value_exists('user', 'username', username):
            raise Exception("User already exists")
        # r = self.cur.execute("SELECT COUNT(username) FROM user WHERE username = ?", (username)).fetchall()
        # if r[0][0] > 0:
        #    raise Exception("User already exists")
        self.cur.execute("INSERT INTO USER (username, salt, password) VALUES (?, ?, ?)", (username, salt, password))

        return True

    def update_user(self, username, salt, password):
        self.cur.execute("UPDATE user SET salt = ?, password = ? WHERE username = ?", (salt, password, username))

    def get_user(self, username):
        pass

    def delete_user(self, username):
        self.cur.execute("DELETE FROM user WHERE username = ?", (username, ))

    def new_secret(self, name, account_name, secret, description):
        if self.value_exists('secret', 'name', name):
            raise ItemExistsError
            # raise Exception("secret already exists")
        self.cur.execute("""INSERT INTO
                         secret (name, account_name, secret, description) 
                         values 
                         (?, ?, ?, ?)""",
                         (name, account_name, secret, description))
        return True

    def update_secret(self, name, account_name, secret, description):
        pass

    def get_secret(self, name):
        pass

    def delete_secret(self, name):
        pass

    def new_role(self, name, description):
        pass

    def update_role(self, name, description):
        pass

    def delete_role(self, name):
        pass

    def new_client(self, name, role, public_key):
        pass

    def update_client(self, name, role, public_key):
        pass

    def delete_client(self, name):
        pass
