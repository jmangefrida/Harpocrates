'''
Log.py
'''

import sqlite3


class Log():
    TYPE = {'security': 'security_log'}

    def __init__(self):
        self.con = sqlite3.connect('log.db', check_same_thread=False)
        self.cur = self.con.cursor()
        self.build_schema()
        #self.add(LogEvent(self,action='service start', outcome="success", msg="Logging service started"))

    def __del__(self):
        # self.add(LogEvent(self,action='service stop', outcome="success", msg="Logging service stopped"))
        pass

    def build_schema(self):
        self.cur.execute("""CREATE TABLE IF NOT EXISTS security_log ( 
                            event_time  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            subject     LONG VARCHAR,
                            object      LONG VARCHAR,
                            access_point LONG VARCHAR,
                            action      LONG VARCHAR,
                            outcome     LONG VARCHAR,
                            msg         TEXT)""")

        self.cur.execute("""CREATE INDEX IF NOT EXISTS idx_security_log ON security_log ( event_time )""")

        self.con.commit()

    def _add_local(self, event):
        if event.type not in Log.TYPE.keys():
            raise TypeError("Log type not found")

        query = "INSERT INTO {} (subject, object, access_point, action, outcome, msg) VALUES (?, ?, ?, ?, ?, ?)"

        query = query.format(Log.TYPE['security'])
        print(query)

        self.cur.execute(query, (event.subject, event.object, event.access_point, event.action, event.outcome, event.msg))
        self.con.commit()

    def add(self, event):
        self._add_local(event)


logger = Log()
