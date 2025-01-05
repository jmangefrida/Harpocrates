import srv.log as log


class LogEvent(object):
    def __init__(self, type='security', subject='', event_object='', access_point='', action='', outcome='', msg=''):
        # self.log = log
        self.type = type
        self.subject = subject
        self.event_object = event_object
        self.access_point = access_point
        self.action = action
        self.outcome = outcome
        self.msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *exec_info):
        log.logger.add(self)

    def save(self):
        log.logger.add(self)

    # def success(self):
    #     self.outcome = 'success'
    #     log.add(self)

    # def fail(self):
    #     self.outcome = 'fail'
    #     self.log.add(self)


def log_event(func):
    def inn_log(*args, **kwargs):
        event = LogEvent(subject=kwargs['subject'],
                         access_point=kwargs['access_point'], 
                         action=func.__name__, 
                         event_object=kwargs['event_object'])
        del kwargs['subject']
        del kwargs['access_point']
        del kwargs['event_object']
        outcome = func(*args, **kwargs)
        if outcome is True:
            event.outcome = 'success'
        else:
            event.outcome = 'fail'
        event.save()
        return outcome
    return inn_log