"""Device schedules use the practice computer's local clock. No cloud cron."""
from datetime import datetime

def due(schedule, state, moment=None):
    moment=moment or datetime.now().astimezone()
    if schedule['kind']=='interval':
        return moment.timestamp()-state.get('last_attempt',0)>=schedule['minutes']*60
    # A date/time slot is executed only once, including a DST fall-back repeat.
    slot=moment.strftime('%Y-%m-%d')+'T'+schedule['time']
    hh,mm=map(int,schedule['time'].split(':'))
    return (moment.weekday() in schedule['days'] and (moment.hour,moment.minute)>=(hh,mm)
            and state.get('last_slot')!=slot)

def mark_attempt(schedule,state,moment=None):
    moment=moment or datetime.now().astimezone()
    state['last_attempt']=moment.timestamp()
    if schedule['kind']=='daily':state['last_slot']=moment.strftime('%Y-%m-%d')+'T'+schedule['time']
