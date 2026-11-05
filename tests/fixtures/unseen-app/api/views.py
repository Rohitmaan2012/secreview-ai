import pickle
import subprocess
from flask import request

DEBUG = True

def load(blob):
    return pickle.loads(blob)

def search(cursor):
    q = request.args.get("q")
    cursor.execute(f"SELECT * FROM items WHERE title = '{q}'")
    return cursor.fetchall()

def convert(name):
    subprocess.run("convert " + name, shell=True)
