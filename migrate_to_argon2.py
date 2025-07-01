import json
from argon2 import PasswordHasher

# 初始化 PasswordHasher
ph = PasswordHasher()

# 密碼哈希函數
def hash_password(password):
    return ph.hash(password)

# 已知的明文密碼（根據之前的 users.json）
plain_passwords = {
    "安妮醬": "puddingmouse77@gmail.com",
    "暖羊": "gauiyu@gmail.com",
    "鴨肉畫字": "judy9002166@gmail.com",
    "POM": "pomponggirl529@gmail.com",
    "來點動物": "orderzoostudio@gmail.com",
    "灰黑集白": "info@aastalee.com",
    "Mi Stile": "l3666362@gmail.com",
    "脈脈": "sasha.chen.sc@gmail.com",
    "好築藝": "lucy61009@gmail.com",
    "月半糰子": "tsai59266@gmail.com",
    "弍榯槭": "woodlife.27.sq@gmail.com",
    "簡約編織": "flyonsky1060224@gmail.com",
    "小潑珠串": "yi1128520@gmail.com",
    "Yuye語頁": "yuye3275@gmail.com",
    "殊遇花藝": "flora6440@yahoo.com.tw",
    "1B H5手工寵物領巾": "minah.kir@gmail.com",
    "5Centimeters": "service@5centimeters.tw",
    "Coisini": "ppoiu123ighv@gmail.com"
}

# 遷移 users.json
with open('users.json', 'r', encoding='utf-8') as f:
    users = json.load(f)

new_users = {}
for username, data in users.items():
    plain_pwd = plain_passwords.get(username, "未知（請重設密碼）")
    hashed_pwd = hash_password(plain_pwd)
    new_users[username] = {
        'user_id': data['user_id'],
        'password': hashed_pwd,
        'commission': data['commission']
    }

with open('users.json', 'w', encoding='utf-8') as f:
    json.dump(new_users, f, indent=4, ensure_ascii=False)

# 遷移 admin.json
with open('admin.json', 'r', encoding='utf-8') as f:
    admins = json.load(f)

new_admins = {}
for username, data in admins.items():
    plain_pwd = "admin55688"  # 管理員的明文密碼
    hashed_pwd = hash_password(plain_pwd)
    new_admins[username] = {
        'password': hashed_pwd,
        'role': data['role']
    }

with open('admin.json', 'w', encoding='utf-8') as f:
    json.dump(new_admins, f, indent=4, ensure_ascii=False)

print("密碼遷移完成！")