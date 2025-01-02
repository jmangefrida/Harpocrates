"""
store.py

"""

import sqlite3


class ItemExistsError(Exception):
    pass


class Store(object):
    """docstring for Store"""
    SETTINGS = ['pre_register', 'restrict_ip', 'external_log']
    
    def __init__(self):
        super(Store, self).__init__()
        self.con = sqlite3.connect("store.db", check_same_thread=False)
        self.cur = self.con.cursor()
        self.build_schema()
        self.popluate_initial_values()
        # print(self.cur.execute("select username from user where username = 'testadmin'", ()).fetchall())

    def build_schema(self):
        # con = sqlite3.connect("store.db", check_same_thread=False)
        # cur = self.con.cursor()
        
        self.cur.execute("""CREATE TABLE IF NOT EXISTS user(
                         username VARCHAR(32) PRIMARY KEY,
                         salt BLOB,
                         enc_key BLOB,
                         register_date DATETIME,
                         last_pass_change DATETIME,
                         account_type VARCHAR(32))""")
        self.cur.execute("""CREATE TABLE IF NOT EXISTS setting(
                         name VARCHAR(255) PRIMARY KEY,
                         value VARCHAR(255))""")
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
        self.con.commit()

    def popluate_initial_values(self):
        for setting in Store.SETTINGS:
            self.cur.execute('INSERT OR IGNORE INTO setting (name, value) values (?, ?)', (setting, ''))
        self.con.commit()

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
        # marks, filters = Store.encode_filters(filters)
        # query = "SELECT {} from {} where {}".format(fields, table, marks)
        # result = self.cur.execute(query, filters).fetchall()
        # print(result)
        query = "SELECT {} from {}".format(fields, table)
        result = self.cur.execute(query, ()).fetchall()

        return result

    def read(self, table, fields, filters):
        fields = ', '.join(fields)
        marks, filters = Store.encode_filters(filters)
        if len(filters) > 0:
            query = "SELECT {} from {} where {}".format(fields, table, marks)
        else:
            query = "SELECT {} from {}".format(fields, table)
        print(query)
        print(filters)
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
        self.con.commit()
        # r = self.cur.execute('select * from user', ()).fetchall()
        print("updated")
        # for row in r:
        #     print(row)
        #self.con.close()
        return True

    def delete(self, table, filters):
        marks, filters = Store.encode_filters(filters)
        query = "DELETE FROM {} WHERE {}".format(table, marks)
        self.cur.execute(query, filters)
        self.con.commit()
        return True

    def execute(self, query, filters):
        # return self.cur.execute(query, filters).fetchall()
        pass

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
