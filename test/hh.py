import ctypes
import threading
import time

_hh = ctypes.CDLL("build/libhh.so")

_hh.hh_init.argtypes = ()
_hh.hh_init.restype = ctypes.c_int

_hh.hh_listen.argtypes = ()
_hh.hh_listen.restype = ctypes.c_int

_hh.hh_cleanup.argtypes = ()
_hh.hh_cleanup.restype = ctypes.c_int

def init():
    if _hh.hh_init() != 0:
        raise Exception("hh_init() failed")

def listen():
    if _hh.hh_listen() != 0:
        raise Exception("hh_listen() failed")

def cleanup():
    if _hh.hh_cleanup() != 0:
        raise Exception("hh_cleanup() failed")

def run():
    init()
    listen()
    cleanup()

def run_async():
    thread = threading.Thread(target=run, args=())
    thread.daemon = True
    thread.start()
    time.sleep(0.5)
