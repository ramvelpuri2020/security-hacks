# Deliberately vulnerable — used only as a PATCH demo/testing fixture.
import os
import pickle
import subprocess
import yaml


def run_backup(user_path):
    # BAD: os.system with user-controlled path (command injection)
    os.system("tar -czf backup.tar.gz " + user_path)


def install(package_name):
    # BAD: subprocess with shell=True (command injection)
    subprocess.run("pip install " + package_name, shell=True)


def load_session(raw_bytes):
    # BAD: unpickling untrusted data (deserialization RCE)
    return pickle.loads(raw_bytes)


def parse_config(settings_str):
    # BAD: unsafe yaml.load (yaml deserialization)
    return yaml.load(settings_str)
