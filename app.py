from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, abort, Blueprint
import os
import json
import logging
import re
import tempfile
import shutil
from datetime import datetime
from dateutil.relativedelta import relativedelta
import pandas as pd
from argon2 import PasswordHasher

# ====================
# 基礎設定與工具函式
# ====================
app = Flask(__name__)

# 設定路徑（使用 os.path 確保跨平台相容）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, 'users.json')      # 使用者資料檔案
ADMIN_FILE = os.path.join(BASE_DIR, 'admin.json')      # 管理員資料檔案
USERS_DIR = os.path.join(BASE_DIR, 'users')            # 使用者報表資料目錄
UPLOADS_DIR = os.path.join(BASE_DIR, 'static', 'uploads')  # 上傳檔案目錄
LOGO_FILE = os.path.join(BASE_DIR, 'static', 'logo.jpg') # Logo 檔案
LOGS_DIR = os.path.join(BASE_DIR, 'logs')              # 日誌目錄
PASSWORD_BACKUP_LOG = os.path.join(LOGS_DIR, 'password_backup.log')  # 密碼備份日誌

# 初始化資料夾與檔案
for directory in [USERS_DIR, UPLOADS_DIR, LOGS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)
        logging.info(f"初始化目錄：{directory}")

if os.path.exists(USERS_DIR):
    existing_brands = [d for d in os.listdir(USERS_DIR) if os.path.isdir(os.path.join(USERS_DIR, d))]
    logging.info(f"找到的品牌目錄：{existing_brands}")
else:
    logging.error(f"users 目錄不存在：{USERS_DIR}")

# 初始化 PasswordHasher
ph = PasswordHasher()

def hash_password(password):
    return ph.hash(password)

def check_password(stored_password, provided_password):
    try:
        ph.verify(stored_password, provided_password)
        return True
    except Exception as e:
        return False

# 若檔案不存在則初始化
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump({}, f, ensure_ascii=False)
    logging.info(f"初始化 users.json 檔案：{USERS_FILE}")

if not os.path.exists(ADMIN_FILE):
    admin_data = {
        'admin': {
            'password': hash_password('admin55688'),
            'role': 'super'
        }
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

# 密碼備份日誌
password_backup_logger = logging.getLogger('password_backup')
password_backup_logger.setLevel(logging.INFO)
password_backup_handler = logging.FileHandler(PASSWORD_BACKUP_LOG, encoding='utf-8')
password_backup_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
password_backup_logger.addHandler(password_backup_handler)

def load_users():
    try:
        with open(USERS_FILE, 'r', encoding='utf-8-sig') as f:
            content = f.read().strip()
            logging.debug(f"載入 users.json 原始內容：{content}")
            if not content:
                logging.info("users.json 為空，初始化為 {}")
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"載入 users.json 失敗：{str(e)}")
        logging.info("已重新初始化 users.json 為 {}")
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f, indent=4, ensure_ascii=False)
        return {}

def save_users(users):
    try:
        temp_fd, temp_path = tempfile.mkstemp()
        try:
            with open(temp_fd, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            shutil.move(temp_path, USERS_FILE)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
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

def load_admins():
    try:
        with open(ADMIN_FILE, 'r', encoding='utf-8-sig') as f:
            content = f.read().strip()
            logging.debug(f"載入 admin.json 原始內容：{content}")
            if not content:
                admin_data = {'admin': {'password': hash_password('admin55688'), 'role': 'super'}}
                save_admins(admin_data)
                return admin_data
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"載入 admin.json 失敗：{str(e)}")
        logging.info("已重新初始化 admin.json 為預設管理員")
        admin_data = {'admin': {'password': hash_password('admin55688'), 'role': 'super'}}
        save_admins(admin_data)
        return admin_data

def save_admins(admins):
    try:
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

def check_password_unique(hashed_password, users, exclude_username=None):
    for username, data in users.items():
        if username != exclude_username and data['password'] == hashed_password:
            return False
    return True

def parse_filename(filename):
    match = re.match(r'^(?:(\d{6})\s*(.*?)|(.*?)_?\s*(\d{6}))\.xlsx$', filename)
    if not match:
        return None, None
    if match.group(1):
        year_month = match.group(1)
        username = match.group(2).strip()
    else:
        year_month = match.group(4)
        username = match.group(3).strip()
    month = f"{year_month[:4]}-{year_month[4:]}"
    return username, month

def process_report(file, username, month):
    file_path = os.path.join(UPLOADS_DIR, f"{month}_{username}.xlsx")
    file.save(file_path)
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        return None, f"無法讀取 Excel 檔案：{str(e)}"
    required_columns = ['項目', 'SKU', '銷售額', '數量']
    if not all(col in df.columns for col in required_columns):
        return None, "Excel 檔案缺少必要的欄位！"
    report_data = df[required_columns].to_dict(orient='records')
    for item in report_data:
        item['銷售額'] = float(str(item['銷售額']).replace(',', ''))
        item['數量'] = int(float(str(item['數量']).replace(',', '')))
    try:
        total_sales = sum(item['銷售額'] for item in report_data)
        total_quantity = sum(item['數量'] for item in report_data)
    except (ValueError, TypeError) as e:
        return None, f"Excel 檔案數據格式錯誤：{str(e)}"
    users = load_users()
    commission_rate = float(users[username]['commission']) / 100
    commission = total_sales * commission_rate
    net_amount = total_sales - commission
    total_sales = round(total_sales, 1)
    commission = round(commission, 1)
    net_amount = round(net_amount, 1)
    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    report_file = os.path.join(user_dir, f"{month}.json")
    if os.path.exists(report_file):
        os.remove(report_file)
        logging.info(f"刪除舊報表：{report_file}")
    report = {
        'data': report_data,
        'total_sales': total_sales,
        'total_quantity': total_quantity,
        'commission_rate': commission_rate * 100,
        'commission': commission,
        'net_amount': net_amount
    }
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    return report, None

# ==================================
# 使用 Blueprint 重構管理後台 (admin) 路由
# ==================================
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    logging.debug(f"訪問 /admin/login，方法：{request.method}")
    if request.method == 'GET':
        return render_template('admin_login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    admins = load_admins()
    if username in admins and check_password(admins[username]['password'], password):
        logging.info(f"管理員 {username} 登入")
        return jsonify({'success': True, 'role': admins[username]['role']})
    return jsonify({'error': '用戶名或密碼錯誤！'})

@admin_bp.route('/')
def admin_home():
    logging.debug("訪問 /admin")
    return render_template('admin.html')

@admin_bp.route('/users')
def get_users():
    logging.debug("訪問 /admin/users")
    users = load_users()
    user_list = [
        {
            'username': username,
            'user_id': data['user_id'],
            'commission': data['commission'],
            'hidden': data.get('hidden', False)
        }
        for username, data in users.items()
    ]
    user_list = sorted(user_list, key=lambda x: x['user_id'])
    logging.debug(f"返回品牌列表：{user_list}")
    return jsonify({'users': user_list})

@admin_bp.route('/hide_user', methods=['POST'])
def hide_user():
    logging.debug("訪問 /admin/hide_user")
    data = request.get_json()
    username = data.get('username')
    hide = data.get('hide', True)
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'})
    users[username]['hidden'] = bool(hide)
    save_users(users)
    logging.info(f"品牌 {username} 隱藏狀態設為 {hide}")
    return jsonify({'message': '品牌隱藏狀態已更新！'})

@admin_bp.route('/add_user', methods=['POST'])
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
    hashed_password = hash_password(password)
    if not check_password_unique(hashed_password, users):
        return jsonify({'error': '密碼已存在，請選擇其他密碼！'})
    users[username] = {
        'user_id': user_id,
        'password': hashed_password,
        'commission': commission,
        'hidden': False  # 新增品牌預設不隱藏
    }
    save_users(users)
    password_backup_logger.info(f"用戶 {username} 的新密碼：{password}")
    logging.info(f"管理員新增品牌 {username}")
    return jsonify({'message': '品牌新增成功！'})

# 更新後的編輯功能：允許部分修改（留空則保持原值）
@admin_bp.route('/edit_user', methods=['POST'])
def edit_user():
    logging.debug("訪問 /admin/edit_user")
    data = request.get_json()
    original_username = data.get('username')
    if not original_username:
        return jsonify({'error': '原品牌名稱缺失！'})
    new_username = data.get('new_username', "").strip()
    new_user_id = data.get('new_user_id', "").strip()
    new_password = data.get('new_password', "").strip()
    new_commission = data.get('new_commission', "").strip()
    users = load_users()
    if original_username not in users:
        return jsonify({'error': '品牌不存在！'})
    user = users[original_username]
    # 品牌名稱處理
    if new_username:
        if not re.match(r'^[\u4e00-\u9fff\w\s-]+$', new_username):
            return jsonify({'error': '品牌名只能包含中文、字母、數字、空格和連字符！'})
        if new_username in users and new_username != original_username:
            return jsonify({'error': '新品牌名已存在！'})
    else:
        new_username = original_username
    # 品牌編號處理
    if not new_user_id:
        new_user_id = user.get('user_id')
    # 抽成處理
    if new_commission:
        try:
            commission_val = float(new_commission)
            if commission_val < 0 or commission_val > 100:
                return jsonify({'error': '抽成百分比必須在 0 到 100 之間！'})
        except ValueError:
            return jsonify({'error': '抽成百分比必須是數字！'})
    else:
        commission_val = user.get('commission')
    # 密碼處理
    if new_password:
        hashed_password = hash_password(new_password)
        if not check_password_unique(hashed_password, users, exclude_username=original_username):
            return jsonify({'error': '新密碼已存在，請選擇其他密碼！'})
    else:
        hashed_password = user.get('password')
    updated_user = {
        'user_id': new_user_id,
        'password': hashed_password,
        'commission': commission_val,
        'hidden': user.get('hidden', False)  # 保留原隱藏狀態
    }
    if new_username != original_username:
        users[new_username] = updated_user
        del users[original_username]
    else:
        users[original_username] = updated_user
    save_users(users)
    if new_password:
        password_backup_logger.info(f"用戶 {original_username} 的新密碼：{new_password}")
    logging.info(f"管理員編輯品牌 {original_username} 成功更新為 {new_username}")
    return jsonify({'message': '品牌編輯成功！'})

@admin_bp.route('/delete_user', methods=['POST'])
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

@admin_bp.route('/summary')
def summary_report():
    logging.debug("訪問 /admin/summary")
    try:
        brand_filter = request.args.get('brand', '').strip()
        month_filter = request.args.get('month', '').strip()
        logging.info(f"篩選條件 - 品牌: {brand_filter}, 月份: {month_filter}")
        users = load_users()
        summary_data = []
        logging.info(f"所有品牌（從 users.json）：{list(users.keys())}")
        for username in users.keys():
            if brand_filter and username != brand_filter:
                logging.debug(f"跳過品牌 {username}（不符合篩選條件）")
                continue
            user_dir = os.path.join(USERS_DIR, username)
            if not os.path.exists(user_dir):
                logging.warning(f"品牌 {username} 的報表目錄不存在：{user_dir}")
                continue
            report_files = [f for f in os.listdir(user_dir) if f.endswith('.json')]
            logging.info(f"品牌 {username} 的報表檔案：{report_files}")
            for report_file in report_files:
                month = report_file.replace('.json', '')
                if month_filter and month != month_filter:
                    logging.debug(f"跳過月份 {month}（不符合篩選條件）")
                    continue
                report_path = os.path.join(user_dir, report_file)
                logging.debug(f"處理報表檔案：{report_path}")
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        report = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"無法解析報表檔案 {report_path}：{str(e)}")
                    continue
                except Exception as e:
                    logging.error(f"讀取報表檔案 {report_path} 失敗：{str(e)}")
                    continue
                if 'data' not in report or not isinstance(report['data'], list):
                    logging.error(f"報表 {report_path} 數據格式錯誤：缺少 data 欄位或格式不正確")
                    continue
                summary_data.append({
                    'username': username,
                    'month': month,
                    'total_sales': report.get('total_sales', 0),
                    'total_quantity': report.get('total_quantity', 0),
                    'commission': report.get('commission', 0),
                    'net_amount': report.get('net_amount', 0),
                    'commission_rate': report.get('commission_rate', 0)
                })
                logging.info(f"成功處理報表：品牌 {username}，月份 {month}")
        total_summary = {
            'total_sales': sum(item['total_sales'] for item in summary_data),
            'total_quantity': sum(item['total_quantity'] for item in summary_data),
            'total_commission': sum(item['commission'] for item in summary_data),
            'total_net_amount': sum(item['net_amount'] for item in summary_data)
        }
        logging.info(f"報表彙總完成：共 {len(summary_data)} 筆資料，總銷售額 {total_summary['total_sales']}")
        return jsonify({
            'summary': summary_data,
            'totals': total_summary
        })
    except Exception as e:
        logging.error(f"生成總覽報表失敗：{str(e)}")
        return jsonify({'error': f'生成總覽報表失敗：{str(e)}'}), 500

@admin_bp.route('/summary_page')
def summary_page():
    logging.debug("訪問 /admin/summary_page")
    try:
        return render_template('summary.html')
    except Exception as e:
        logging.error(f"渲染 summary.html 失敗：{str(e)}")
        return jsonify({'error': f'無法渲染總覽報表頁面：{str(e)}'}), 500

@admin_bp.route('/reports/<username>')
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

@admin_bp.route('/upload_report', methods=['POST'])
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

@admin_bp.route('/batch_upload_reports', methods=['POST'])
def batch_upload_reports():
    logging.debug("訪問 /admin/batch_upload_reports")
    files = request.files.getlist('files')
    users = load_users()
    if not files:
        return jsonify({'error': '請選擇至少一個檔案！'})
    success_count = 0
    error_messages = []
    user_map = {username.lower(): username for username in users.keys()}
    for file in files:
        logging.debug(f"處理檔案：{file.filename}")
        username, month = parse_filename(file.filename)
        if not username or not month:
            error_messages.append(f"檔案 {file.filename} 格式錯誤，應為 <年月><品牌名稱>.xlsx 或 <品牌名稱>_<年月>.xlsx（例如：202503安妮醬.xlsx 或 安妮醬_202503.xlsx）")
            continue
        username_lower = username.lower()
        if username_lower not in user_map:
            error_messages.append(f"檔案 {file.filename} 中的品牌 {username} 不存在！")
            continue
        original_username = user_map[username_lower]
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

@admin_bp.route('/upload_logo', methods=['POST'])
def upload_logo():
    logging.debug("訪問 /admin/upload_logo")
    file = request.files.get('file')
    if not file:
        return jsonify({'error': '請選擇檔案！'})
    if not file.filename.endswith('.jpg'):
        return jsonify({'error': '請上傳 JPG 檔案！'})
    file.save(LOGO_FILE)
    return jsonify({'message': 'Logo 上傳成功！'})

@admin_bp.route('/change_password', methods=['POST'])
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
    admins[username]['password'] = hash_password(new_password)
    save_admins(admins)
    password_backup_logger.info(f"管理員 {username} 的新密碼：{new_password}")
    logging.info(f"管理員 {username} 變更密碼")
    return jsonify({'message': '密碼變更成功！'})

@admin_bp.route('/export_summary_excel', methods=['POST'])
def export_summary_excel():
    logging.debug("訪問 /admin/export_summary_excel")
    try:
        data = request.get_json()
        summary_data = data.get('summary', [])
        totals = data.get('totals', {})
        df_data = []
        for item in summary_data:
            df_data.append({
                '品牌名稱': item['username'],
                '月份': item['month'],
                '總銷售額': round(float(item['total_sales']), 1),
                '總數量': item['total_quantity'],
                '抽成百分比 (%)': round(float(item['commission_rate']), 1),
                '總抽成': round(float(item['commission']), 1),
                '總實匯金額': round(float(item['net_amount']), 1)
            })
        df_data.append({})
        df_data.append({
            '品牌名稱': '總計',
            '月份': '-',
            '總銷售額': round(float(totals['total_sales']), 1),
            '總數量': totals['total_quantity'],
            '抽成百分比 (%)': '-',
            '總抽成': round(float(totals['total_commission']), 1),
            '總實匯金額': round(float(totals['total_net_amount']), 1)
        })
        df = pd.DataFrame(df_data)
        temp_file = "總覽報表.xlsx"
        temp_path = os.path.join(tempfile.gettempdir(), temp_file)
        with pd.ExcelWriter(temp_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='總覽報表')
            worksheet = writer.sheets['總覽報表']
            for col in worksheet.columns:
                max_length = 0
                column = col[0].column_letter
                for cell in col:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = (max_length + 2) * 1.2
                worksheet.column_dimensions[column].width = adjusted_width
            from openpyxl.styles import Font
            font = Font(name='新細明體', size=12)
            for row in worksheet.rows:
                for cell in row:
                    cell.font = font
        response = send_file(temp_path, as_attachment=True, download_name=temp_file)
        try:
            os.remove(temp_path)
        except Exception as e:
            logging.warning(f"無法刪除臨時檔案 {temp_path}：{str(e)}")
        return response
    except Exception as e:
        logging.error(f"匯出總覽報表失敗：{str(e)}")
        return jsonify({'error': f'匯出總覽報表失敗：{str(e)}'}), 500

# ==================================
# 使用 Blueprint 重構品牌頁面 (view) 路由
# ==================================
view_bp = Blueprint('view', __name__, url_prefix='/view')

@view_bp.route('/')
def view_home():
    logging.debug("訪問 /view")
    return render_template('view.html')

@view_bp.route('/users')
def view_users():
    logging.debug("訪問 /view/users")
    users = load_users()
    # 只顯示未隱藏品牌
    user_list = [
        {'username': username, 'user_id': data['user_id']}
        for username, data in users.items()
        if not data.get('hidden', False)
    ]
    # 依 user_id 排序
    user_list = sorted(user_list, key=lambda x: x['user_id'])
    logging.debug(f"返回品牌列表：{user_list}")
    return jsonify({'users': user_list})

@view_bp.route('/verify', methods=['POST'])
def verify_user():
    logging.debug("訪問 /view/verify")
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_users()
    admins = load_admins()
    if username not in users:
        return jsonify({'error': '品牌名或密碼錯誤！'})
    user_password_match = check_password(users[username]['password'], password)
    admin_password_match = False
    if 'admin' in admins:
        admin_password_match = check_password(admins['admin']['password'], password)
    if user_password_match or admin_password_match:
        logging.info(f"品牌 {username} 登入（{'管理員密碼' if admin_password_match else '用戶密碼'}）")
        return jsonify({'success': True})
    return jsonify({'error': '品牌名或密碼錯誤！'})

@view_bp.route('/reports/<username>')
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
    try:
        users = load_users()
        if username not in users:
            return jsonify({'error': '品牌不存在！'}), 404
        report_file = os.path.join(USERS_DIR, username, f"{month}.json")
        if not os.path.exists(report_file):
            return jsonify({'error': '報表不存在！'}), 404
        with open(report_file, 'r', encoding='utf-8') as f:
            report = json.load(f)
        if 'data' not in report or not isinstance(report['data'], list):
            return jsonify({'error': '報表數據格式錯誤：缺少 data 欄位或格式不正確'}), 500
        try:
            report['data'] = sorted(report['data'], key=lambda x: float(str(x.get('銷售額', 0)).replace(',', '')), reverse=True)
        except (ValueError, KeyError) as e:
            logging.error(f"排序報表數據失敗：{str(e)}")
            return jsonify({'error': f'排序報表數據失敗：{str(e)}'}), 500
        return jsonify(report)
    except json.JSONDecodeError as e:
        logging.error(f"無法解析報表檔案 {report_file}：{str(e)}")
        return jsonify({'error': f'無法解析報表檔案：{str(e)}'}), 500
    except Exception as e:
        logging.error(f"載入報表失敗：{str(e)}")
        return jsonify({'error': f'載入報表失敗：{str(e)}'}), 500

@app.route('/download_report_excel/<username>/<month>')
def download_report_excel(username, month):
    logging.debug(f"訪問 /download_report_excel/{username}/{month}")
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'}), 404
    report_file = os.path.join(USERS_DIR, username, f"{month}.json")
    if not os.path.exists(report_file):
        return jsonify({'error': '報表不存在！'}), 404
    with open(report_file, 'r', encoding='utf-8') as f:
        report = json.load(f)
    df = pd.DataFrame(report['data'])
    summary = pd.DataFrame([{
        '項目': '總計',
        'SKU': '',
        '銷售額': report['total_sales'],
        '數量': report['total_quantity']
    }])
    df = pd.concat([df, summary], ignore_index=True)
    temp_file = f"{username}_{month}_report.xlsx"
    temp_path = os.path.join(tempfile.gettempdir(), temp_file)
    with pd.ExcelWriter(temp_path, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    response = send_file(temp_path, as_attachment=True, download_name=temp_file)
    try:
        os.remove(temp_path)
    except PermissionError as e:
        logging.warning(f"無法刪除臨時檔案 {temp_path}：{str(e)}")
    except Exception as e:
        logging.error(f"刪除臨時檔案 {temp_path} 時發生錯誤：{str(e)}")
    return response

# 關於 gunicorn -w 4 -b 0.0.0.0:10000 app:app 的說明

# 這是部署 Flask 應用到生產環境時常用的指令，意思如下：
# -w 4         # 啟動 4 個 worker 處理請求（可依主機 CPU 調整）
# -b 0.0.0.0:10000  # 綁定所有網卡的 10000 埠口
# app:app      # 匯入 app.py 檔案中的 app 物件

# 若你在本地開發，直接用 python app.py 即可，不需要 gunicorn。
# 若你在 Render、Heroku、Docker 等生產環境，建議用 gunicorn 來啟動 Flask，這樣效能與穩定性較佳。

# 結論：
# - 本地開發：不用設定 gunicorn，直接 python app.py
# - 生產部署：建議用 gunicorn -w 4 -b 0.0.0.0:10000 app:app
# - 若 Render 平台要求用 gunicorn，則必須設定

# ====================
# 註冊 Blueprint 與根路由
# ====================
app.register_blueprint(admin_bp)
app.register_blueprint(view_bp)

@app.route('/')
def index():
    # 直接顯示品牌頁面，不再做重導
    return render_template('view.html')

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    # 使用 port 5002 運行
    app.run(debug=True, host='0.0.0.0', port=5002)
app.register_blueprint(admin_bp)
app.register_blueprint(view_bp)

@app.route('/')
@app.route('/')
def index():
    # 直接顯示品牌頁面，不再做重導
    return render_template('view.html')

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    # 使用 port 5002 運行
    app.run(debug=True, host='0.0.0.0', port=5002)
@app.route('/')
def index():
    # 直接顯示品牌頁面，不再做重導
    return render_template('view.html')

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    # 使用 port 5002 運行
    app.run(debug=True, host='0.0.0.0', port=5002)
if not os.path.exists(ADMIN_FILE):
    admin_data = {
        'admin': {
            'password': hash_password('admin55688'),
            'role': 'super'
        }
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

# 密碼備份日誌
password_backup_logger = logging.getLogger('password_backup')
password_backup_logger.setLevel(logging.INFO)
password_backup_handler = logging.FileHandler(PASSWORD_BACKUP_LOG, encoding='utf-8')
password_backup_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
password_backup_logger.addHandler(password_backup_handler)

def load_users():
    try:
        with open(USERS_FILE, 'r', encoding='utf-8-sig') as f:
            content = f.read().strip()
            logging.debug(f"載入 users.json 原始內容：{content}")
            if not content:
                logging.info("users.json 為空，初始化為 {}")
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"載入 users.json 失敗：{str(e)}")
        logging.info("已重新初始化 users.json 為 {}")
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f, indent=4, ensure_ascii=False)
        return {}

def save_users(users):
    try:
        temp_fd, temp_path = tempfile.mkstemp()
        try:
            with open(temp_fd, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            shutil.move(temp_path, USERS_FILE)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
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

def load_admins():
    try:
        with open(ADMIN_FILE, 'r', encoding='utf-8-sig') as f:
            content = f.read().strip()
            logging.debug(f"載入 admin.json 原始內容：{content}")
            if not content:
                admin_data = {'admin': {'password': hash_password('admin55688'), 'role': 'super'}}
                save_admins(admin_data)
                return admin_data
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"載入 admin.json 失敗：{str(e)}")
        logging.info("已重新初始化 admin.json 為預設管理員")
        admin_data = {'admin': {'password': hash_password('admin55688'), 'role': 'super'}}
        save_admins(admin_data)
        return admin_data

def save_admins(admins):
    try:
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

def check_password_unique(hashed_password, users, exclude_username=None):
    for username, data in users.items():
        if username != exclude_username and data['password'] == hashed_password:
            return False
    return True

def parse_filename(filename):
    match = re.match(r'^(?:(\d{6})\s*(.*?)|(.*?)_?\s*(\d{6}))\.xlsx$', filename)
    if not match:
        return None, None
    if match.group(1):
        year_month = match.group(1)
        username = match.group(2).strip()
    else:
        year_month = match.group(4)
        username = match.group(3).strip()
    month = f"{year_month[:4]}-{year_month[4:]}"
    return username, month

def process_report(file, username, month):
    file_path = os.path.join(UPLOADS_DIR, f"{month}_{username}.xlsx")
    file.save(file_path)
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        return None, f"無法讀取 Excel 檔案：{str(e)}"
    required_columns = ['項目', 'SKU', '銷售額', '數量']
    if not all(col in df.columns for col in required_columns):
        return None, "Excel 檔案缺少必要的欄位！"
    report_data = df[required_columns].to_dict(orient='records')
    for item in report_data:
        item['銷售額'] = float(str(item['銷售額']).replace(',', ''))
        item['數量'] = int(float(str(item['數量']).replace(',', '')))
    try:
        total_sales = sum(item['銷售額'] for item in report_data)
        total_quantity = sum(item['數量'] for item in report_data)
    except (ValueError, TypeError) as e:
        return None, f"Excel 檔案數據格式錯誤：{str(e)}"
    users = load_users()
    commission_rate = float(users[username]['commission']) / 100
    commission = total_sales * commission_rate
    net_amount = total_sales - commission
    total_sales = round(total_sales, 1)
    commission = round(commission, 1)
    net_amount = round(net_amount, 1)
    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    report_file = os.path.join(user_dir, f"{month}.json")
    if os.path.exists(report_file):
        os.remove(report_file)
        logging.info(f"刪除舊報表：{report_file}")
    report = {
        'data': report_data,
        'total_sales': total_sales,
        'total_quantity': total_quantity,
        'commission_rate': commission_rate * 100,
        'commission': commission,
        'net_amount': net_amount
    }
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    return report, None

# ==================================
# 使用 Blueprint 重構管理後台 (admin) 路由
# ==================================
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    logging.debug(f"訪問 /admin/login，方法：{request.method}")
    if request.method == 'GET':
        return render_template('admin_login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    admins = load_admins()
    if username in admins and check_password(admins[username]['password'], password):
        logging.info(f"管理員 {username} 登入")
        return jsonify({'success': True, 'role': admins[username]['role']})
    return jsonify({'error': '用戶名或密碼錯誤！'})

@admin_bp.route('/')
def admin_home():
    logging.debug("訪問 /admin")
    return render_template('admin.html')

@admin_bp.route('/users')
def get_users():
    logging.debug("訪問 /admin/users")
    users = load_users()
    user_list = [
        {
            'username': username,
            'user_id': data['user_id'],
            'commission': data['commission'],
            'hidden': data.get('hidden', False)
        }
        for username, data in users.items()
    ]
    user_list = sorted(user_list, key=lambda x: x['user_id'])
    logging.debug(f"返回品牌列表：{user_list}")
    return jsonify({'users': user_list})

@admin_bp.route('/hide_user', methods=['POST'])
def hide_user():
    logging.debug("訪問 /admin/hide_user")
    data = request.get_json()
    username = data.get('username')
    hide = data.get('hide', True)
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'})
    users[username]['hidden'] = bool(hide)
    save_users(users)
    logging.info(f"品牌 {username} 隱藏狀態設為 {hide}")
    return jsonify({'message': '品牌隱藏狀態已更新！'})

@admin_bp.route('/add_user', methods=['POST'])
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
    hashed_password = hash_password(password)
    if not check_password_unique(hashed_password, users):
        return jsonify({'error': '密碼已存在，請選擇其他密碼！'})
    users[username] = {
        'user_id': user_id,
        'password': hashed_password,
        'commission': commission,
        'hidden': False  # 新增品牌預設不隱藏
    }
    save_users(users)
    password_backup_logger.info(f"用戶 {username} 的新密碼：{password}")
    logging.info(f"管理員新增品牌 {username}")
    return jsonify({'message': '品牌新增成功！'})

# 更新後的編輯功能：允許部分修改（留空則保持原值）
@admin_bp.route('/edit_user', methods=['POST'])
def edit_user():
    logging.debug("訪問 /admin/edit_user")
    data = request.get_json()
    original_username = data.get('username')
    if not original_username:
        return jsonify({'error': '原品牌名稱缺失！'})
    new_username = data.get('new_username', "").strip()
    new_user_id = data.get('new_user_id', "").strip()
    new_password = data.get('new_password', "").strip()
    new_commission = data.get('new_commission', "").strip()
    users = load_users()
    if original_username not in users:
        return jsonify({'error': '品牌不存在！'})
    user = users[original_username]
    # 品牌名稱處理
    if new_username:
        if not re.match(r'^[\u4e00-\u9fff\w\s-]+$', new_username):
            return jsonify({'error': '品牌名只能包含中文、字母、數字、空格和連字符！'})
        if new_username in users and new_username != original_username:
            return jsonify({'error': '新品牌名已存在！'})
    else:
        new_username = original_username
    # 品牌編號處理
    if not new_user_id:
        new_user_id = user.get('user_id')
    # 抽成處理
    if new_commission:
        try:
            commission_val = float(new_commission)
            if commission_val < 0 or commission_val > 100:
                return jsonify({'error': '抽成百分比必須在 0 到 100 之間！'})
        except ValueError:
            return jsonify({'error': '抽成百分比必須是數字！'})
    else:
        commission_val = user.get('commission')
    # 密碼處理
    if new_password:
        hashed_password = hash_password(new_password)
        if not check_password_unique(hashed_password, users, exclude_username=original_username):
            return jsonify({'error': '新密碼已存在，請選擇其他密碼！'})
    else:
        hashed_password = user.get('password')
    updated_user = {
        'user_id': new_user_id,
        'password': hashed_password,
        'commission': commission_val,
        'hidden': user.get('hidden', False)  # 保留原隱藏狀態
    }
    if new_username != original_username:
        users[new_username] = updated_user
        del users[original_username]
    else:
        users[original_username] = updated_user
    save_users(users)
    if new_password:
        password_backup_logger.info(f"用戶 {original_username} 的新密碼：{new_password}")
    logging.info(f"管理員編輯品牌 {original_username} 成功更新為 {new_username}")
    return jsonify({'message': '品牌編輯成功！'})

@admin_bp.route('/delete_user', methods=['POST'])
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

@admin_bp.route('/summary')
def summary_report():
    logging.debug("訪問 /admin/summary")
    try:
        brand_filter = request.args.get('brand', '').strip()
        month_filter = request.args.get('month', '').strip()
        logging.info(f"篩選條件 - 品牌: {brand_filter}, 月份: {month_filter}")
        users = load_users()
        summary_data = []
        logging.info(f"所有品牌（從 users.json）：{list(users.keys())}")
        for username in users.keys():
            if brand_filter and username != brand_filter:
                logging.debug(f"跳過品牌 {username}（不符合篩選條件）")
                continue
            user_dir = os.path.join(USERS_DIR, username)
            if not os.path.exists(user_dir):
                logging.warning(f"品牌 {username} 的報表目錄不存在：{user_dir}")
                continue
            report_files = [f for f in os.listdir(user_dir) if f.endswith('.json')]
            logging.info(f"品牌 {username} 的報表檔案：{report_files}")
            for report_file in report_files:
                month = report_file.replace('.json', '')
                if month_filter and month != month_filter:
                    logging.debug(f"跳過月份 {month}（不符合篩選條件）")
                    continue
                report_path = os.path.join(user_dir, report_file)
                logging.debug(f"處理報表檔案：{report_path}")
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        report = json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"無法解析報表檔案 {report_path}：{str(e)}")
                    continue
                except Exception as e:
                    logging.error(f"讀取報表檔案 {report_path} 失敗：{str(e)}")
                    continue
                if 'data' not in report or not isinstance(report['data'], list):
                    logging.error(f"報表 {report_path} 數據格式錯誤：缺少 data 欄位或格式不正確")
                    continue
                summary_data.append({
                    'username': username,
                    'month': month,
                    'total_sales': report.get('total_sales', 0),
                    'total_quantity': report.get('total_quantity', 0),
                    'commission': report.get('commission', 0),
                    'net_amount': report.get('net_amount', 0),
                    'commission_rate': report.get('commission_rate', 0)
                })
                logging.info(f"成功處理報表：品牌 {username}，月份 {month}")
        total_summary = {
            'total_sales': sum(item['total_sales'] for item in summary_data),
            'total_quantity': sum(item['total_quantity'] for item in summary_data),
            'total_commission': sum(item['commission'] for item in summary_data),
            'total_net_amount': sum(item['net_amount'] for item in summary_data)
        }
        logging.info(f"報表彙總完成：共 {len(summary_data)} 筆資料，總銷售額 {total_summary['total_sales']}")
        return jsonify({
            'summary': summary_data,
            'totals': total_summary
        })
    except Exception as e:
        logging.error(f"生成總覽報表失敗：{str(e)}")
        return jsonify({'error': f'生成總覽報表失敗：{str(e)}'}), 500

@admin_bp.route('/summary_page')
def summary_page():
    logging.debug("訪問 /admin/summary_page")
    try:
        return render_template('summary.html')
    except Exception as e:
        logging.error(f"渲染 summary.html 失敗：{str(e)}")
        return jsonify({'error': f'無法渲染總覽報表頁面：{str(e)}'}), 500

@admin_bp.route('/reports/<username>')
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

@admin_bp.route('/upload_report', methods=['POST'])
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

@admin_bp.route('/batch_upload_reports', methods=['POST'])
def batch_upload_reports():
    logging.debug("訪問 /admin/batch_upload_reports")
    files = request.files.getlist('files')
    users = load_users()
    if not files:
        return jsonify({'error': '請選擇至少一個檔案！'})
    success_count = 0
    error_messages = []
    user_map = {username.lower(): username for username in users.keys()}
    for file in files:
        logging.debug(f"處理檔案：{file.filename}")
        username, month = parse_filename(file.filename)
        if not username or not month:
            error_messages.append(f"檔案 {file.filename} 格式錯誤，應為 <年月><品牌名稱>.xlsx 或 <品牌名稱>_<年月>.xlsx（例如：202503安妮醬.xlsx 或 安妮醬_202503.xlsx）")
            continue
        username_lower = username.lower()
        if username_lower not in user_map:
            error_messages.append(f"檔案 {file.filename} 中的品牌 {username} 不存在！")
            continue
        original_username = user_map[username_lower]
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

@admin_bp.route('/upload_logo', methods=['POST'])
def upload_logo():
    logging.debug("訪問 /admin/upload_logo")
    file = request.files.get('file')
    if not file:
        return jsonify({'error': '請選擇檔案！'})
    if not file.filename.endswith('.jpg'):
        return jsonify({'error': '請上傳 JPG 檔案！'})
    file.save(LOGO_FILE)
    return jsonify({'message': 'Logo 上傳成功！'})

@admin_bp.route('/change_password', methods=['POST'])
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
    admins[username]['password'] = hash_password(new_password)
    save_admins(admins)
    password_backup_logger.info(f"管理員 {username} 的新密碼：{new_password}")
    logging.info(f"管理員 {username} 變更密碼")
    return jsonify({'message': '密碼變更成功！'})

@admin_bp.route('/export_summary_excel', methods=['POST'])
def export_summary_excel():
    logging.debug("訪問 /admin/export_summary_excel")
    try:
        data = request.get_json()
        summary_data = data.get('summary', [])
        totals = data.get('totals', {})
        df_data = []
        for item in summary_data:
            df_data.append({
                '品牌名稱': item['username'],
                '月份': item['month'],
                '總銷售額': round(float(item['total_sales']), 1),
                '總數量': item['total_quantity'],
                '抽成百分比 (%)': round(float(item['commission_rate']), 1),
                '總抽成': round(float(item['commission']), 1),
                '總實匯金額': round(float(item['net_amount']), 1)
            })
        df_data.append({})
        df_data.append({
            '品牌名稱': '總計',
            '月份': '-',
            '總銷售額': round(float(totals['total_sales']), 1),
            '總數量': totals['total_quantity'],
            '抽成百分比 (%)': '-',
            '總抽成': round(float(totals['total_commission']), 1),
            '總實匯金額': round(float(totals['total_net_amount']), 1)
        })
        df = pd.DataFrame(df_data)
        temp_file = "總覽報表.xlsx"
        temp_path = os.path.join(tempfile.gettempdir(), temp_file)
        with pd.ExcelWriter(temp_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='總覽報表')
            worksheet = writer.sheets['總覽報表']
            for col in worksheet.columns:
                max_length = 0
                column = col[0].column_letter
                for cell in col:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = (max_length + 2) * 1.2
                worksheet.column_dimensions[column].width = adjusted_width
            from openpyxl.styles import Font
            font = Font(name='新細明體', size=12)
            for row in worksheet.rows:
                for cell in row:
                    cell.font = font
        response = send_file(temp_path, as_attachment=True, download_name=temp_file)
        try:
            os.remove(temp_path)
        except Exception as e:
            logging.warning(f"無法刪除臨時檔案 {temp_path}：{str(e)}")
        return response
    except Exception as e:
        logging.error(f"匯出總覽報表失敗：{str(e)}")
        return jsonify({'error': f'匯出總覽報表失敗：{str(e)}'}), 500

# ==================================
# 使用 Blueprint 重構品牌頁面 (view) 路由
# ==================================
view_bp = Blueprint('view', __name__, url_prefix='/view')

@view_bp.route('/')
def view_home():
    logging.debug("訪問 /view")
    return render_template('view.html')

@view_bp.route('/users')
def view_users():
    logging.debug("訪問 /view/users")
    users = load_users()
    # 只顯示未隱藏品牌
    user_list = [
        {'username': username, 'user_id': data['user_id']}
        for username, data in users.items()
        if not data.get('hidden', False)
    ]
    # 依 user_id 排序
    user_list = sorted(user_list, key=lambda x: x['user_id'])
    logging.debug(f"返回品牌列表：{user_list}")
    return jsonify({'users': user_list})

@view_bp.route('/verify', methods=['POST'])
def verify_user():
    logging.debug("訪問 /view/verify")
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_users()
    admins = load_admins()
    if username not in users:
        return jsonify({'error': '品牌名或密碼錯誤！'})
    user_password_match = check_password(users[username]['password'], password)
    admin_password_match = False
    if 'admin' in admins:
        admin_password_match = check_password(admins['admin']['password'], password)
    if user_password_match or admin_password_match:
        logging.info(f"品牌 {username} 登入（{'管理員密碼' if admin_password_match else '用戶密碼'}）")
        return jsonify({'success': True})
    return jsonify({'error': '品牌名或密碼錯誤！'})

@view_bp.route('/reports/<username>')
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
    try:
        users = load_users()
        if username not in users:
            return jsonify({'error': '品牌不存在！'}), 404
        report_file = os.path.join(USERS_DIR, username, f"{month}.json")
        if not os.path.exists(report_file):
            return jsonify({'error': '報表不存在！'}), 404
        with open(report_file, 'r', encoding='utf-8') as f:
            report = json.load(f)
        if 'data' not in report or not isinstance(report['data'], list):
            return jsonify({'error': '報表數據格式錯誤：缺少 data 欄位或格式不正確'}), 500
        try:
            report['data'] = sorted(report['data'], key=lambda x: float(str(x.get('銷售額', 0)).replace(',', '')), reverse=True)
        except (ValueError, KeyError) as e:
            logging.error(f"排序報表數據失敗：{str(e)}")
            return jsonify({'error': f'排序報表數據失敗：{str(e)}'}), 500
        return jsonify(report)
    except json.JSONDecodeError as e:
        logging.error(f"無法解析報表檔案 {report_file}：{str(e)}")
        return jsonify({'error': f'無法解析報表檔案：{str(e)}'}), 500
    except Exception as e:
        logging.error(f"載入報表失敗：{str(e)}")
        return jsonify({'error': f'載入報表失敗：{str(e)}'}), 500

@app.route('/download_report_excel/<username>/<month>')
def download_report_excel(username, month):
    logging.debug(f"訪問 /download_report_excel/{username}/{month}")
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'}), 404
    report_file = os.path.join(USERS_DIR, username, f"{month}.json")
    if not os.path.exists(report_file):
        return jsonify({'error': '報表不存在！'}), 404
    with open(report_file, 'r', encoding='utf-8') as f:
        report = json.load(f)
    df = pd.DataFrame(report['data'])
    summary = pd.DataFrame([{
        '項目': '總計',
        'SKU': '',
        '銷售額': report['total_sales'],
        '數量': report['total_quantity']
    }])
    df = pd.concat([df, summary], ignore_index=True)
    temp_file = f"{username}_{month}_report.xlsx"
    temp_path = os.path.join(tempfile.gettempdir(), temp_file)
    with pd.ExcelWriter(temp_path, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    response = send_file(temp_path, as_attachment=True, download_name=temp_file)
    try:
        os.remove(temp_path)
    except PermissionError as e:
        logging.warning(f"無法刪除臨時檔案 {temp_path}：{str(e)}")
    except Exception as e:
        logging.error(f"刪除臨時檔案 {temp_path} 時發生錯誤：{str(e)}")
    return response

# 關於 gunicorn -w 4 -b 0.0.0.0:10000 app:app 的說明

# 這是部署 Flask 應用到生產環境時常用的指令，意思如下：
# -w 4         # 啟動 4 個 worker 處理請求（可依主機 CPU 調整）
# -b 0.0.0.0:10000  # 綁定所有網卡的 10000 埠口
# app:app      # 匯入 app.py 檔案中的 app 物件

# 若你在本地開發，直接用 python app.py 即可，不需要 gunicorn。
# 若你在 Render、Heroku、Docker 等生產環境，建議用 gunicorn 來啟動 Flask，這樣效能與穩定性較佳。

# 結論：
# - 本地開發：不用設定 gunicorn，直接 python app.py
# - 生產部署：建議用 gunicorn -w 4 -b 0.0.0.0:10000 app:app
# - 若 Render 平台要求用 gunicorn，則必須設定

# ====================
# 註冊 Blueprint 與根路由
# ====================
app.register_blueprint(admin_bp)
app.register_blueprint(view_bp)

@app.route('/')
def index():
    # 直接顯示品牌頁面，不再做重導
    return render_template('view.html')

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    # 使用 port 5002 運行
    app.run(debug=True, host='0.0.0.0', port=5002)
    app.run(debug=True, host='0.0.0.0', port=5002)
@app.route('/')
def index():
    # 直接顯示品牌頁面，不再做重導
    return render_template('view.html')

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    # 使用 port 5002 運行
    app.run(debug=True, host='0.0.0.0', port=5002)

# 註冊 Blueprint 與根路由
# ====================
app.register_blueprint(admin_bp)
app.register_blueprint(view_bp)

@app.route('/')
@app.route('/')
def index():
    # 直接顯示品牌頁面，不再做重導
    return render_template('view.html')

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    # 使用 port 5002 運行
    app.run(debug=True, host='0.0.0.0', port=5002)
@app.route('/')
def index():
    # 直接顯示品牌頁面，不再做重導
    return render_template('view.html')

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    # 使用 port 5002 運行
    app.run(debug=True, host='0.0.0.0', port=5002)
