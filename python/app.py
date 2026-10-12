import os

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def run_expression(expr):
    return eval(expr)

def load_config(path):
    with open(path) as f:
        return f.read()

def exec_cmd(cmd):
    os.system("ls " + cmd)
