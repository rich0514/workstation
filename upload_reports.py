import requests
import os

# Render 環境的 URL
BASE_URL = "https://createlife.onrender.com"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin55688"

# 登入管理員
def login():
    response = requests.post(f"{BASE_URL}/admin/login", data={
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD
    })
    if response.status_code == 200 and response.json().get("success"):
        print("管理員登入成功")
        return response.cookies
    else:
        raise Exception("管理員登入失敗")

# 上傳報表檔案
def upload_reports():
    cookies = login()
    files_dir = "f:/workstation/static/uploads"
    files = [f for f in os.listdir(files_dir) if f.endswith('.xlsx')]
    for file_name in files:
        file_path = os.path.join(files_dir, file_name)
        with open(file_path, 'rb') as f:
            response = requests.post(
                f"{BASE_URL}/admin/batch_upload_reports",
                files={'files': (file_name, f, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')},
                cookies=cookies
            )
        if response.status_code == 200:
            print(f"成功上傳報表：{file_name}")
        else:
            print(f"上傳報表失敗：{file_name}，錯誤：{response.text}")

if __name__ == "__main__":
    upload_reports()