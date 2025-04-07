import json

# 密碼哈希函數
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# 遷移 users.json
with open('users.json', 'r', encoding='utf-8') as f:
    users = json.load(f)

new_users = {}
for username, data in users.items():
    new_users[username] = {
        'user_id': data['user_id'],
        'password': data['hashed_password'],  # 使用哈希密碼
        'commission': data['commission']
    }

with open('users.json', 'w', encoding='utf-8') as f:
    json.dump(new_users, f, indent=4, ensure_ascii=False)

# 遷移 admin.json
with open('admin.json', 'r', encoding='utf-8') as f:
    admins = json.load(f)

new_admins = {}
for username, data in admins.items():
    new_admins[username] = {
        'password': data['hashed_password'],  # 使用哈希密碼
        'role': data['role']
    }

with open('admin.json', 'w', encoding='utf-8') as f:
    json.dump(new_admins, f, indent=4, ensure_ascii=False)

print("遷移完成！")