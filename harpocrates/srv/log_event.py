import srv.log as log


class LogEvent():
    def __init__(self, type='security', subject='', object='', access_point='', action='', outcome='', msg=''):
        # self.log = log
        self.type = type
        self.subject = subject
        self.object = object
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


def log_event(func):
    def inn_log(*args, **kwargs):
        print('logging')
        print(kwargs)
        print(args)
        event = LogEvent(subject=kwargs['subject'],
                         access_point=kwargs['access_point'], 
                         action=func.__name__, 
                         object=kwargs['object'])
        # del kwargs['subject']
        # del kwargs['access_point']
        # del kwargs['event_object']
        outcome = func(*args, **kwargs)[0]
        if outcome is True:
            event.outcome = 'success'
        else:
            event.outcome = 'fail'
        event.save()
        return outcome
    return inn_log
