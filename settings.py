from json import dumps as dd, dump as d, load as l, loads as ll
from base64 import b16decode as dc, b16encode as ec
import os, random

class settings(object):
    def __init__(self):
        self.a = f"{os.path.dirname(__file__)}/settings.json" # a way of getting the settings.json file without the main.py script being ran in the relative directory
        self.b = l(open(self.a))
        self.c = self.b.get('DATA',None)
        
        if self.c is None:
            print("WARNING: corrupt data file")
            buf = ec("{'online': 'true'}".encode('utf-8')).decode('utf-8')
            self.b['DATA'] = buf
            self.c = buf
        
    def load_to_env(self):
        os.environ[f'DIVISIONBUF_parisma_{random.randint(0,999999)}'] = self.c