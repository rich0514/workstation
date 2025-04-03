from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, abort
import os
import json
import logging
import time
import re
import tempfile
import shutil
from datetime import datetime
from dateutil.relativedelta import relativedelta
import pandas as pd

app = Flask(__name__)

# 設定路徑（使用 os.path 確保跨平台兼容）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
ADMIN_FILE = os.path.join(BASE_DIR, 'admin.json')
USERS_DIR = os.path.join(BASE_DIR, 'users')
UPLOADS_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
LOGO_FILE = os.path.join(BASE_DIR, 'static', 'logo.jpg')

# 初始化資料夾和檔案
for directory in [USERS_DIR, UPLOADS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump({}, f, ensure_ascii=False)
    logging.info(f"初始化 users.json 檔案：{USERS_FILE}")

if not os.path.exists(ADMIN_FILE):
    # 預設管理員：admin/admin123，最高權限
    admin_data = {
        'admin': {'password': 'admin123', 'role': 'super'}
    }
    with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
        json.dump(admin_data, f, ensure_ascii=False)
    logging.info(f"初始化 admin.json 檔案：{ADMIN_FILE}")

# 設定日誌
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, 'debug.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# 讀取用戶資料
def load_users():
    try:
        with open(USERS_FILE, 'r', encoding='utf-8-sig') as f:
            content = f.read().strip()
            logging.debug(f"載入 users.json 原始內容：{content}")
            if not content:  # 如果檔案為空，初始化為空物件
                logging.info("users.json 為空，初始化為 {}")
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"載入 users.json 失敗：{str(e)}")
        raise Exception(f"無法載入 users.json：{str(e)}")

# 儲存用戶資料
def save_users(users):
    try:
        # 使用臨時檔案寫入，確保原子性
        temp_fd, temp_path = tempfile.mkstemp()
        try:
            with open(temp_fd, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            # 將臨時檔案移動到目標位置
            shutil.move(temp_path, USERS_FILE)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # 驗證寫入是否成功
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                raise IOError("寫入 users.json 後檔案為空")
            loaded_data = json.loads(content)
            if loaded_data != users:
                raise IOError("寫入 users.json 後內容不一致")
        logging.debug(f"儲存 users.json 成功：{users}")
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"儲存 users.json 失敗：{str(e)}")
        raise

# 讀取管理員資料
def load_admins():
    try:
        with open(ADMIN_FILE, 'r', encoding='utf-8-sig') as f:
            content = f.read().strip()
            logging.debug(f"載入 admin.json 原始內容：{content}")
            if not content:  # 如果檔案為空，初始化為預設管理員
                admin_data = {
                    'admin': {'password': 'admin123', 'role': 'super'}
                }
                save_admins(admin_data)
                return admin_data
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"載入 admin.json 失敗：{str(e)}")
        raise Exception(f"無法載入 admin.json：{str(e)}")

# 儲存管理員資料
def save_admins(admins):
    try:
        # 使用臨時檔案寫入，確保原子性
        temp_fd, temp_path = tempfile.mkstemp()
        try:
            with open(temp_fd, 'w', encoding='utf-8') as f:
                json.dump(admins, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            shutil.move(temp_path, ADMIN_FILE)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        logging.debug(f"儲存 admin.json 成功：{admins}")
    except IOError as e:
        logging.error(f"儲存 admin.json 失敗：{str(e)}")
        raise

# 檢查密碼是否重複
def check_password_unique(password, users, exclude_username=None):
    for username, data in users.items():
        if username != exclude_username and data['password'] == password:
            return False
    return True

# 檢查品牌編號是否重複
def check_user_id_unique(user_id, users, exclude_username=None):
    for username, data in users.items():
        if username != exclude_username and data['user_id'] == user_id:
            return False
    return True

# 解析檔名
def parse_filename(filename):
    match = re.match(r'(\d{6})(.+)\.xlsx$', filename)
    if not match:
        return None, None
    year_month = match.group(1)
    username = match.group(2)
    month = f"{year_month[:4]}-{year_month[4:]}"
    return username, month

# 處理報表上傳
def process_report(file, username, month):
    # 儲存上傳的檔案
    file_path = os.path.join(UPLOADS_DIR, f"{month}_{username}.xlsx")
    file.save(file_path)

    # 讀取 Excel 檔案
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        return None, f"無法讀取 Excel 檔案：{str(e)}"

    required_columns = ['項目', 'SKU', '銷售額', '數量']
    if not all(col in df.columns for col in required_columns):
        return None, "Excel 檔案缺少必要的欄位！"

    # 提取報表資料
    report_data = df[required_columns].to_dict(orient='records')

    # 計算總計，處理千位分隔符並確保數據為數字類型
    try:
        total_sales = sum(float(str(item['銷售額']).replace(',', '')) for item in report_data)
        # 允許數量欄位為浮點數，先轉為 float 再轉為 int
        total_quantity = sum(int(float(str(item['數量']).replace(',', ''))) for item in report_data)
    except (ValueError, TypeError) as e:
        return None, f"Excel 檔案數據格式錯誤：{str(e)}"

    # 計算抽成和實匯金額
    users = load_users()
    commission_rate = float(users[username]['commission']) / 100
    commission = total_sales * commission_rate
    net_amount = total_sales - commission

    # 四捨五入到小數點第一位
    total_sales = round(total_sales, 1)
    commission = round(commission, 1)
    net_amount = round(net_amount, 1)

    # 儲存報表
    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    report_file = os.path.join(user_dir, f"{month}.json")
    # 如果報表已存在，刪除舊檔案
    if os.path.exists(report_file):
        os.remove(report_file)
        logging.info(f"刪除舊報表：{report_file}")
    report = {
        'data': report_data,
        'total_sales': total_sales,
        'total_quantity': total_quantity,
        'commission_rate': commission_rate * 100,  # 儲存百分比
        'commission': commission,
        'net_amount': net_amount
    }
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    return report, None

@app.route('/')
def index():
    logging.debug("訪問首頁 /")
    return redirect(url_for('view'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    logging.debug(f"訪問 /admin/login，方法：{request.method}")
    if request.method == 'GET':
        return render_template('admin_login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    admins = load_admins()
    if username in admins and admins[username]['password'] == password:
        logging.info(f"管理員 {username} 登入")
        return jsonify({'success': True, 'role': admins[username]['role']})
    return jsonify({'error': '用戶名或密碼錯誤！'})

@app.route('/admin')
def admin():
    logging.debug("訪問 /admin")
    return render_template('admin.html')

@app.route('/admin/users')
def get_users():
    logging.debug("訪問 /admin/users")
    users = load_users()
    user_list = [{'username': username, 'user_id': data['user_id'], 'commission': data['commission']} for username, data in users.items()]
    # 按 user_id 排序
    user_list = sorted(user_list, key=lambda x: x['user_id'])
    logging.debug(f"返回品牌列表：{user_list}")
    return jsonify({'users': user_list})

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    logging.debug("訪問 /admin/add_user")
    data = request.get_json()
    username = data.get('username')
    user_id = data.get('user_id')
    password = data.get('password')
    commission = data.get('commission')

    if not username or not user_id or not password or not commission:
        return jsonify({'error': '請填寫所有欄位！'})

    if not re.match(r'^[\u4e00-\u9fff\w\s-]+$', username):
        return jsonify({'error': '品牌名只能包含中文、字母、數字、空格和連字符！'})

    try:
        commission = float(commission)
        if commission < 0 or commission > 100:
            return jsonify({'error': '抽成百分比必須在 0 到 100 之間！'})
    except ValueError:
        return jsonify({'error': '抽成百分比必須是數字！'})

    users = load_users()
    if username in users:
        return jsonify({'error': '品牌名已存在！'})

    # 檢查品牌編號是否重複
    if not check_user_id_unique(user_id, users):
        return jsonify({'error': '品牌編號已存在！'})

    if not check_password_unique(password, users):
        return jsonify({'error': '密碼已存在，請選擇其他密碼！'})

    users[username] = {
        'user_id': user_id,
        'password': password,
        'commission': commission
    }
    save_users(users)
    logging.info(f"管理員新增品牌 {username}")
    return jsonify({'message': '品牌新增成功！'})

@app.route('/admin/edit_user', methods=['POST'])
def edit_user():
    logging.debug("訪問 /admin/edit_user")
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    commission = data.get('commission')

    if not password or not commission:
        return jsonify({'error': '請填寫所有欄位！'})

    try:
        commission = float(commission)
        if commission < 0 or commission > 100:
            return jsonify({'error': '抽成百分比必須在 0 到 100 之間！'})
    except ValueError:
        return jsonify({'error': '抽成百分比必須是數字！'})

    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'})

    if not check_password_unique(password, users, exclude_username=username):
        return jsonify({'error': '密碼已存在，請選擇其他密碼！'})

    users[username]['password'] = password
    users[username]['commission'] = commission
    save_users(users)
    logging.info(f"管理員編輯品牌 {username}")
    return jsonify({'message': '品牌編輯成功！'})

@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    logging.debug("訪問 /admin/delete_user")
    data = request.get_json()
    username = data.get('username')

    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'})

    del users[username]
    save_users(users)

    user_dir = os.path.join(USERS_DIR, username)
    if os.path.exists(user_dir):
        for file in os.listdir(user_dir):
            os.remove(os.path.join(user_dir, file))
        os.rmdir(user_dir)

    logging.info(f"管理員刪除品牌 {username}")
    return jsonify({'message': '品牌刪除成功！'})

@app.route('/admin/reports/<username>')
def admin_reports(username):
    logging.debug(f"訪問 /admin/reports/{username}")
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'}), 404

    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        return render_template('report.html', username=username, months=[])

    months = [f.split('.json')[0] for f in os.listdir(user_dir) if f.endswith('.json')]
    months.sort()
    return render_template('report.html', username=username, months=months)

@app.route('/admin/upload_report', methods=['POST'])
def upload_report():
    logging.debug("訪問 /admin/upload_report")
    username = request.form.get('username')
    month = request.form.get('month')
    file = request.files.get('file')

    if not username or not month or not file:
        return jsonify({'error': '請填寫所有欄位！'})

    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'})

    report, error = process_report(file, username, month)
    if error:
        return jsonify({'error': error})

    logging.info(f"管理員上傳報表：品牌 {username}，月份 {month}")
    return jsonify({'message': '報表上傳成功！'})

@app.route('/admin/batch_upload_reports', methods=['POST'])
def batch_upload_reports():
    logging.debug("訪問 /admin/batch_upload_reports")
    files = request.files.getlist('files')
    users = load_users()

    if not files:
        return jsonify({'error': '請選擇至少一個檔案！'})

    success_count = 0
    error_messages = []

    # 建立品牌名稱的映射（大小寫不敏感）
    user_map = {username.lower(): username for username in users.keys()}

    for file in files:
        logging.debug(f"處理檔案：{file.filename}")
        # 根據檔案名稱辨識品牌和月份
        username, month = parse_filename(file.filename)
        if not username or not month:
            error_messages.append(f"檔案 {file.filename} 格式錯誤，應為 <年月><品牌名稱>.xlsx（例如：202503安妮醬.xlsx）")
            continue

        # 大小寫不敏感比較品牌名稱
        username_lower = username.lower()
        if username_lower not in user_map:
            error_messages.append(f"檔案 {file.filename} 中的品牌 {username} 不存在！")
            continue

        # 使用原始品牌名稱（保持大小寫一致）
        original_username = user_map[username_lower]

        # 處理報表
        report, error = process_report(file, original_username, month)
        if error:
            error_messages.append(f"檔案 {file.filename} 上傳失敗：{error}")
        else:
            success_count += 1
            logging.info(f"批量上傳報表成功：品牌 {original_username}，月份 {month}")

    if success_count == len(files):
        return jsonify({'message': f'成功上傳 {success_count} 個報表！'})
    else:
        return jsonify({
            'message': f'成功上傳 {success_count} 個報表，失敗 {len(files) - success_count} 個。',
            'errors': error_messages
        })

@app.route('/admin/upload_logo', methods=['POST'])
def upload_logo():
    logging.debug("訪問 /admin/upload_logo")
    file = request.files.get('file')
    if not file:
        return jsonify({'error': '請選擇檔案！'})

    if not file.filename.endswith('.jpg'):
        return jsonify({'error': '請上傳 JPG 檔案！'})

    file.save(LOGO_FILE)
    return jsonify({'message': 'Logo 上傳成功！'})

@app.route('/admin/change_password', methods=['POST'])
def change_password():
    logging.debug("訪問 /admin/change_password")
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')

    if not username or not new_password:
        return jsonify({'error': '請填寫所有欄位！'})

    admins = load_admins()
    if username not in admins:
        return jsonify({'error': '管理員不存在！'})

    admins[username]['password'] = new_password
    save_admins(admins)
    logging.info(f"管理員 {username} 變更密碼")
    return jsonify({'message': '密碼變更成功！'})

@app.route('/view')
def view():
    logging.debug("訪問 /view")
    return render_template('view.html')

@app.route('/view/users')
def view_users():
    logging.debug("訪問 /view/users")
    users = load_users()
    user_list = [{'username': username, 'user_id': data['user_id']} for username, data in users.items()]
    # 按 user_id 排序
    user_list = sorted(user_list, key=lambda x: x['user_id'])
    logging.debug(f"返回品牌列表：{user_list}")
    return jsonify({'users': user_list})

@app.route('/view/verify', methods=['POST'])
def verify_user():
    logging.debug("訪問 /view/verify")
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    users = load_users()
    if username not in users or users[username]['password'] != password:
        return jsonify({'error': '品牌名或密碼錯誤！'})

    logging.info(f"品牌 {username} 登入")
    return jsonify({'success': True})

@app.route('/view/reports/<username>')
def view_reports(username):
    logging.debug(f"訪問 /view/reports/{username}")
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'}), 404

    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        return render_template('report.html', username=username, months=[])

    months = [f.split('.json')[0] for f in os.listdir(user_dir) if f.endswith('.json')]
    months.sort()
    return render_template('report.html', username=username, months=months)

@app.route('/report/<username>/<month>')
def get_report(username, month):
    logging.debug(f"訪問 /report/{username}/{month}")
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'}), 404

    report_file = os.path.join(USERS_DIR, username, f"{month}.json")
    if not os.path.exists(report_file):
        return jsonify({'error': '報表不存在！'}), 404

    with open(report_file, 'r', encoding='utf-8') as f:
        report = json.load(f)
    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)