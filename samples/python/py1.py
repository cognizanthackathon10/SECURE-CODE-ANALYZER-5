import os
import sys
import pickle
import subprocess

user_input = input("Enter code: ")
eval(user_input) 

with open("data.pkl", "rb") as f:
    obj = pickle.load(f)  


cmd = input("Enter shell command: ")
subprocess.call(cmd, shell=True) 

arg = sys.argv[1]
os.system(arg)