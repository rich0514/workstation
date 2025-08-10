from flask import Flask, render_template, request, jsonify, send_file, Blueprint, redirect, url_for
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
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
ADMIN_FILE = os.path.join(BASE_DIR, 'admin.json')
USERS_DIR = os.path.join(BASE_DIR, 'users')
UPLOADS_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
LOGO_FILE = os.path.join(BASE_DIR, 'static', 'logo.jpg')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
PASSWORD_BACKUP_LOG = os.path.join(LOGS_DIR, 'password_backup.log')

# 初始化 PasswordHasher
ph = PasswordHasher()

# ====================
# 重構後的通用檔案處理函式
# 原始的 load_users/save_users 函式被此通用函式取代
# ====================
def _load_json(file_path, default_data=None):
    """
    通用函式，用於從 JSON 檔案載入資料。
    會處理檔案不存在、格式錯誤或為空的情況，並預設使用 UTF-8 編碼。
    """
    try:
        if not os.path.exists(file_path):
            logging.warning(f"檔案不存在：{file_path}，使用預設資料。")
            if default_data is not None:
                _save_json(file_path, default_data)
            return default_data
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                logging.warning(f"檔案 {file_path} 為空，返回預設資料。")
                if default_data is not None:
                    _save_json(file_path, default_data)
                return default_data
            
            # 修正：將非法 JSON 格式的 NaN 替換為合法的 null
            content = re.sub(r'\bNaN\b', 'null', content)
            
            return json.loads(content)
    except (json.JSONDecodeError, IOError, UnicodeDecodeError) as e:
        logging.error(f"載入 {file_path} 失敗：{str(e)}，已嘗試重新初始化。")
        if default_data is not None:
            _save_json(file_path, default_data)
        return default_data

def _save_json(file_path, data):
    """
    通用函式，用於以原子方式將資料儲存到 JSON 檔案。
    使用臨時檔案以確保寫入過程中斷不會損壞原始檔案。
    """
    try:
        temp_dir = os.path.dirname(file_path)
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        temp_fd, temp_path = tempfile.mkstemp(dir=temp_dir)
        try:
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            shutil.move(temp_path, file_path)
            logging.debug(f"成功儲存檔案：{file_path}")
        except Exception as e:
            logging.error(f"寫入臨時檔案失敗：{str(e)}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
    except Exception as e:
        logging.error(f"儲存 {file_path} 失敗：{str(e)}")
        raise

# 原始的 load/save 函式，現在內部呼叫通用函式
def load_users():
    return _load_json(USERS_FILE, {})

def save_users(users):
    return _save_json(USERS_FILE, users)

def load_admins():
    default_admin_data = {'admin': {'password': hash_password('admin55688'), 'role': 'super'}}
    return _load_json(ADMIN_FILE, default_admin_data)

def save_admins(admins):
    return _save_json(ADMIN_FILE, admins)

def hash_password(password):
    return ph.hash(password)

def check_password(stored_password, provided_password):
    try:
        ph.verify(stored_password, provided_password)
        return True
    except Exception:
        return False

# ====================
# 應用程式啟動初始化
# ====================
def initialize_app():
    """初始化所有必要的目錄和檔案。"""
    for directory in [USERS_DIR, UPLOADS_DIR, LOGS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"初始化目錄：{directory}")
    load_users()
    load_admins()

# ====================
# 其他通用工具函式
# ====================
def check_password_unique(hashed_password, users, exclude_username=None):
    """檢查新密碼是否與現有密碼重複。"""
    for username, data in users.items():
        if username != exclude_username and data['password'] == hashed_password:
            return False
    return True

def parse_filename(filename):
    """從檔案名稱中解析出品牌名稱和月份。"""
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
    """處理上傳的 Excel 檔案，計算並儲存報表。"""
    file_path = os.path.join(UPLOADS_DIR, f"{month}_{username}.xlsx")
    file.save(file_path)
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        return None, f"無法讀取 Excel 檔案：{str(e)}"
    required_columns = ['項目', 'SKU', '銷售額', '數量']
    if not all(col in df.columns for col in required_columns):
        return None, "Excel 檔案缺少必要的欄位！"
    df = df[df['項目'].astype(str).str.strip() != '總計']
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
    _save_json(report_file, report)
    return report, None

# ====================
# 重構後的通用報表渲染函式
# ====================
def _render_user_reports_page(username):
    """共用的報表頁面處理邏輯"""
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'}), 404
    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        return render_template('report.html', username=username, months=[])
    months = sorted([f.split('.json')[0] for f in os.listdir(user_dir) if f.endswith('.json')])
    return render_template('report.html', username=username, months=months)

# ====================
# 日誌設定
# ====================
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, 'debug.log'), encoding='utf-8'),
        logging.StreamHandler()
    ]
)
password_backup_logger = logging.getLogger('password_backup')
password_backup_logger.setLevel(logging.INFO)
password_backup_handler = logging.FileHandler(PASSWORD_BACKUP_LOG, encoding='utf-8')
password_backup_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
password_backup_logger.addHandler(password_backup_handler)

# ====================
# 管理員路由 (Blueprint)
# ====================
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
def admin_home():
    return render_template('admin.html')

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    admins = load_admins()
    if username in admins and check_password(admins[username]['password'], password):
        logging.info(f"管理員 {username} 登入")
        return jsonify({'success': True, 'role': admins[username]['role']})
    return jsonify({'error': '用戶名或密碼錯誤！'})

@admin_bp.route('/users')
def get_users():
    users = load_users()
    user_list = [{'username': u, 'user_id': d['user_id'], 'commission': d['commission'], 'hidden': d.get('hidden', False)} for u, d in users.items()]
    user_list.sort(key=lambda x: x['user_id'])
    return jsonify({'users': user_list})

@admin_bp.route('/hide_user', methods=['POST'])
def hide_user():
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
        'hidden': False
    }
    save_users(users)
    password_backup_logger.info(f"用戶 {username} 的新密碼：{password}")
    logging.info(f"管理員新增品牌 {username}")
    return jsonify({'message': '品牌新增成功！'})

@admin_bp.route('/edit_user', methods=['POST'])
def edit_user():
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
    if new_username:
        if not re.match(r'^[\u4e00-\u9fff\w\s-]+$', new_username):
            return jsonify({'error': '品牌名只能包含中文、字母、數字、空格和連字符！'})
        if new_username in users and new_username != original_username:
            return jsonify({'error': '新品牌名已存在！'})
    else:
        new_username = original_username
    if not new_user_id:
        new_user_id = user.get('user_id')
    if new_commission:
        try:
            commission_val = float(new_commission)
            if commission_val < 0 or commission_val > 100:
                return jsonify({'error': '抽成百分比必須在 0 到 100 之間！'})
        except ValueError:
            return jsonify({'error': '抽成百分比必須是數字！'})
    else:
        commission_val = user.get('commission')
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
        'hidden': user.get('hidden', False)
    }
    if new_username != original_username:
        users[new_username] = updated_user
        del users[original_username]
        original_user_dir = os.path.join(USERS_DIR, original_username)
        if os.path.exists(original_user_dir):
            new_user_dir = os.path.join(USERS_DIR, new_username)
            os.rename(original_user_dir, new_user_dir)
            logging.info(f"更名品牌目錄：{original_user_dir} -> {new_user_dir}")
    else:
        users[original_username] = updated_user
    save_users(users)
    if new_password:
        password_backup_logger.info(f"用戶 {original_username} 的新密碼：{new_password}")
    logging.info(f"管理員編輯品牌 {original_username} 成功更新為 {new_username}")
    return jsonify({'message': '品牌編輯成功！'})

@admin_bp.route('/delete_user', methods=['POST'])
def delete_user():
    data = request.get_json()
    username = data.get('username')
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'})
    del users[username]
    save_users(users)
    user_dir = os.path.join(USERS_DIR, username)
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)
        logging.info(f"刪除品牌 {username} 的資料目錄：{user_dir}")
    logging.info(f"管理員刪除品牌 {username}")
    return jsonify({'message': '品牌刪除成功！'})

@admin_bp.route('/summary')
def summary_report():
    try:
        brand_filter = request.args.get('brand', '').strip()
        month_filter = request.args.get('month', '').strip()
        logging.info(f"篩選條件 - 品牌: {brand_filter}, 月份: {month_filter}")
        users = load_users()
        summary_data = []
        for username in users.keys():
            if brand_filter and username != brand_filter:
                continue
            user_dir = os.path.join(USERS_DIR, username)
            if not os.path.exists(user_dir):
                logging.warning(f"品牌 {username} 的報表目錄不存在：{user_dir}")
                continue
            report_files = [f for f in os.listdir(user_dir) if f.endswith('.json')]
            for report_file in report_files:
                month = report_file.replace('.json', '')
                if month_filter and month != month_filter:
                    continue
                report_path = os.path.join(user_dir, report_file)
                try:
                    report = _load_json(report_path)
                    if 'data' not in report or not isinstance(report['data'], list):
                        logging.error(f"報表 {report_path} 數據格式錯誤")
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
                except Exception as e:
                    logging.error(f"讀取報表檔案 {report_path} 失敗：{str(e)}")
        total_summary = {
            'total_sales': sum(item['total_sales'] for item in summary_data),
            'total_quantity': sum(item['total_quantity'] for item in summary_data),
            'total_commission': sum(item['commission'] for item in summary_data),
            'total_net_amount': sum(item['net_amount'] for item in summary_data)
        }
        return jsonify({
            'summary': summary_data,
            'totals': total_summary
        })
    except Exception as e:
        logging.error(f"生成總覽報表失敗：{str(e)}")
        return jsonify({'error': f'生成總覽報表失敗：{str(e)}'}), 500

@admin_bp.route('/summary_page')
def summary_page():
    return render_template('summary.html')

@admin_bp.route('/reports/<username>')
def admin_reports(username):
    return _render_user_reports_page(username)

@admin_bp.route('/upload_report', methods=['POST'])
def upload_report():
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
    files = request.files.getlist('files')
    users = load_users()
    if not files:
        return jsonify({'error': '請選擇至少一個檔案！'})
    success_count = 0
    error_messages = []
    user_map = {username.lower(): username for username in users.keys()}
    for file in files:
        username, month = parse_filename(file.filename)
        if not username or not month:
            error_messages.append(f"檔案 {file.filename} 格式錯誤，應為 <年月><品牌名稱>.xlsx 或 <品牌名稱>_<年月>.xlsx")
            continue
        original_username = user_map.get(username.lower())
        if not original_username:
            error_messages.append(f"檔案 {file.filename} 中的品牌 {username} 不存在！")
            continue
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
    file = request.files.get('file')
    if not file:
        return jsonify({'error': '請選擇檔案！'})
    if not file.filename.endswith('.jpg'):
        return jsonify({'error': '請上傳 JPG 檔案！'})
    file.save(LOGO_FILE)
    return jsonify({'message': 'Logo 上傳成功！'})

@admin_bp.route('/change_password', methods=['POST'])
def change_password():
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
        response = send_file(temp_path, as_attachment=True, download_name=temp_file, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        os.remove(temp_path)
        return response
    except Exception as e:
        logging.error(f"匯出總覽報表失敗：{str(e)}")
        return jsonify({'error': f'匯出總覽報表失敗：{str(e)}'}), 500

@admin_bp.route('/batch_add_users', methods=['POST'])
def batch_add_users():
    """
    批量新增品牌，接受 Excel 檔案，欄位需包含：品牌名稱、品牌編號、密碼、抽成百分比
    """
    file = request.files.get('file')
    if not file:
        return jsonify({'error': '請選擇 Excel 檔案！'})
    try:
        df = pd.read_excel(file)
    except Exception as e:
        return jsonify({'error': f'無法讀取 Excel 檔案：{str(e)}'})
    required_columns = ['品牌名稱', '品牌編號', '密碼', '抽成百分比']
    for col in required_columns:
        if col not in df.columns:
            return jsonify({'error': f'Excel 檔案缺少必要欄位：{col}'})
    users = load_users()
    added = 0
    errors = []
    for idx, row in df.iterrows():
        username = str(row['品牌名稱']).strip()
        user_id = str(row['品牌編號']).strip()
        password = str(row['密碼']).strip()
        commission = row['抽成百分比']
        if not username or not user_id or not password or commission == '':
            errors.append(f"第{idx+2}行資料不完整，已略過")
            continue
        if not re.match(r'^[\u4e00-\u9fff\w\s-]+$', username):
            errors.append(f"第{idx+2}行品牌名稱格式錯誤，已略過")
            continue
        try:
            commission = float(commission)
            if commission < 0 or commission > 100:
                errors.append(f"第{idx+2}行抽成百分比需在0~100之間，已略過")
                continue
        except Exception:
            errors.append(f"第{idx+2}行抽成百分比格式錯誤，已略過")
            continue
        if username in users:
            errors.append(f"第{idx+2}行品牌名稱已存在，已略過")
            continue
        hashed_password = hash_password(password)
        if not check_password_unique(hashed_password, users):
            errors.append(f"第{idx+2}行密碼已存在，已略過")
            continue
        users[username] = {
            'user_id': user_id,
            'password': hashed_password,
            'commission': commission,
            'hidden': False
        }
        password_backup_logger.info(f"用戶 {username} 的新密碼：{password}")
        added += 1
    save_users(users)
    msg = f"成功新增 {added} 個品牌"
    if errors:
        msg += f"，有 {len(errors)} 筆資料未匯入"
    return jsonify({'message': msg, 'errors': errors})

# ====================
# 品牌用戶路由 (Blueprint)
# ====================
view_bp = Blueprint('view', __name__, url_prefix='/view')

@view_bp.route('/')
def view_home():
    return render_template('view.html')

@view_bp.route('/users')
def view_users():
    users = load_users()
    user_list = [
        {'username': username, 'user_id': data['user_id']}
        for username, data in users.items()
        if not data.get('hidden', False)
    ]
    user_list = sorted(user_list, key=lambda x: x['user_id'])
    return jsonify({'users': user_list})

@view_bp.route('/verify', methods=['POST'])
def verify_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_users()
    admins = load_admins()
    if username not in users:
        return jsonify({'error': '品牌名或密碼錯誤！'})
    user_password_match = check_password(users[username]['password'], password)
    admin_password_match = admins and 'admin' in admins and check_password(admins['admin']['password'], password)
    if user_password_match or admin_password_match:
        logging.info(f"品牌 {username} 登入（{'管理員密碼' if admin_password_match else '用戶密碼'}）")
        return jsonify({'success': True})
    return jsonify({'error': '品牌名或密碼錯誤！'})

@view_bp.route('/reports/<username>')
def view_reports(username):
    return _render_user_reports_page(username)

# 新增：品牌小卡點擊跳轉密碼頁
@view_bp.route('/enter/<username>')
def enter_password(username):
    return render_template('enter_password.html', username=username)

@view_bp.route('/verify_and_redirect', methods=['POST'])
def verify_and_redirect():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = load_users()
    admins = load_admins()
    if username not in users:
        return jsonify({'error': '品牌名或密碼錯誤！'})
    user_password_match = check_password(users[username]['password'], password)
    admin_password_match = admins and 'admin' in admins and check_password(admins['admin']['password'], password)
    if user_password_match or admin_password_match:
        return jsonify({'success': True, 'redirect': url_for('view.view_reports', username=username)})
    return jsonify({'error': '品牌名或密碼錯誤！'})

# ====================
# 根路由和報表 API
# ====================
@app.route('/')
def index():
    return redirect(url_for('view.view_home'))

@app.route('/report/<username>/<month>')
def get_report(username, month):
    try:
        users = load_users()
        if username not in users:
            return jsonify({'error': '品牌不存在！'}), 404
        report_file = os.path.join(USERS_DIR, username, f"{month}.json")
        if not os.path.exists(report_file):
            return jsonify({'error': '報表不存在！'}), 404
        report = _load_json(report_file)
        if 'data' not in report or not isinstance(report['data'], list):
            return jsonify({'error': '報表數據格式錯誤'}), 500
        report['data'] = [item for item in report['data'] if str(item.get('項目', '')).strip() != '總計']
        report['data'] = sorted(report['data'], key=lambda x: float(str(x.get('銷售額', 0)).replace(',', '')), reverse=True)
        return jsonify(report)
    except Exception as e:
        logging.error(f"載入報表失敗：{str(e)}")
        return jsonify({'error': f'載入報表失敗：{str(e)}'}), 500

@app.route('/download_report_excel/<username>/<month>')
def download_report_excel(username, month):
    users = load_users()
    if username not in users:
        return jsonify({'error': '品牌不存在！'}), 404
    report_file = os.path.join(USERS_DIR, username, f"{month}.json")
    if not os.path.exists(report_file):
        return jsonify({'error': '報表不存在！'}), 404
    report = _load_json(report_file)
    df = pd.DataFrame(report['data'])
    summary = pd.DataFrame([{\
        '項目': '總計',\
        'SKU': '',\
        '銷售額': report['total_sales'],\
        '數量': report['total_quantity']\
    }])
    df = pd.concat([df, summary], ignore_index=True)
    temp_file = f"{username}_{month}_report.xlsx"
    temp_path = os.path.join(tempfile.gettempdir(), temp_file)
    with pd.ExcelWriter(temp_path, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    response = send_file(temp_path, as_attachment=True, download_name=temp_file, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    os.remove(temp_path)
    return response

# ====================
# 註冊 Blueprint
# ====================
app.register_blueprint(admin_bp)
app.register_blueprint(view_bp)

# ====================
# 主程序執行
# ====================
if __name__ == '__main__':
    initialize_app()
    app.run(debug=True, host='0.0.0.0', port=5002)
