import win32api
import win32con
import time

def show_notification(title, message):
    win32api.MessageBox(0, message, title, win32con.MB_OK)

show_notification('Spegnimento del computer', 'Il computer si spegnerà tra 30 secondi.')
