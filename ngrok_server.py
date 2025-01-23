import time
from pyngrok import ngrok
import threading

#----------------------------------------------------------------------------------------------------

def start_server(port, event):
    ngrok.set_auth_token("2poAzhdBhUIsEJ6nAPK1FgN2p6o_486mq2uwgRLDeHsKWjiaB")

    tunnel = ngrok.connect(port)

    with open("link.txt", "w") as file:
        file.write(f"{tunnel.public_url}\n")
    
    event.set()

    while True:
        time.sleep(1)

    return None

#----------------------------------------------------------------------------------------------------
