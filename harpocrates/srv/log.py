'''
Log.py
'''

import sqlite3


class Log(object):

    def __init__(self):
        self.con = sqlite3.connect('log.db', check_same_thread=False)
        self.cur = self.con.cursor()

    def build_schema(self):
        pass