import os

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def run_expression(expr):
    return eval(expr)

def load_config(path):
    with open(path) as f:
        return f.read()

def exec_cmd(cmd):
    os.system("ls " + cmd)

def generate_reset_token(email: str) -> str:
    """找回密码令牌生成：时间戳即可预测，演示增量捕获新增缺陷。"""
    import time
    return str(int(time.time())) + email
