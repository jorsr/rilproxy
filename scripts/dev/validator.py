from ril_h import REQUEST, UNSOL

from logging import debug, error

from sismic.exceptions import ExecutionError
from sismic.io import import_from_yaml
from sismic.interpreter import Interpreter
from sismic.model import Event, Statechart


class Validator(object):
    '''Verify that messages adhere to my protocol '''
    def validate(self, ril_msg):
        ''' Run through verifier '''
        call = type(ril_msg).__name__[3:]
        command = ril_msg.command

        # Transfer to function calls
        if call == 'Request':
            event = 'onRequest(' + REQUEST[command] + ')'
        elif call == 'SolicitedResponse':
            event = 'OnRequestComplete(' + REQUEST[command] + ')'
        elif call == 'UnsolicitedResponse':
            event = 'OnUnsolicitedResponse(' + UNSOL[command] + ')'
        elif call == 'Message':
            debug('Message ignored by validator')

            return
        else:
            error('%s not supported by validator', call)

            return

        if event not in self.statechart.events_for():
            raise ExecutionError(
                'Event ' + event +
                ' is not in state machine nor explicitly ignored.')
        step = self.interpreter.queue(Event(event)).execute_once()

        while step:
            if step.transitions:
                transition = step.transitions[0]

                debug('%s - %s -> %s', transition.source, transition.event,
                      transition.target)
            else:
                raise ExecutionError('No valid transition for ' + event +
                                     'from this state.')
            step = self.interpreter.execute_once()

    def __init__(self):
        with open('statecharts/state_machine.yaml') as f:
            self.statechart = import_from_yaml(f)

        assert isinstance(self.statechart, Statechart)

        interpreter = Interpreter(self.statechart)
        interpreter.execute_once()
