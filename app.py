import time
import boto3
from io import BytesIO
from botocore.exceptions import ClientError
from flask import Flask, render_template, send_file, request, session, redirect, url_for, jsonify

S3_BUCKET = "mings-plugins"

app = Flask(__name__)
app.secret_key = 'your-super-secret-key-here'
s3_client = boto3.client("s3")

dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('users')

@app.context_processor
def inject_session():
    return dict(session=session)

def file_size_format(size):
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    i = 0
    while size > 1024:
        size /= 1024
        i += 1
    return f"{size:.2f} {units[i]}"

def get_file_permission(file_path: str):
    if file_path.startswith('SCConflict/'):
        return 'SCConflict'
    elif file_path.startswith('SCConflict-Free/'):
        return '免费'
    elif file_path.startswith('SBPlaceholder2/'):
        return '免费'
    else:
        return '无法获取'

def has_permission(user_email: str, permission: str):
    if permission == '免费': return True
    response = users_table.get_item(
        Key={'username': user_email}
    )
    if 'Item' in response and 'permission' in response['Item']:
        stored_permission = response['Item']['permission']
        for perm in stored_permission:
            if perm == permission:
                return True
    return False

files = []
update_time = None
def update_s3_objects():
    global files
    global update_time
    
    if update_time is not None and time.time() - update_time < 120:
        return
    update_time = time.time()
    
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET)
    except Exception as e:
        print(e)
        return
    if 'Contents' in response:
        files = [
            {
                "key": obj["Key"].split('/')[-1],
                "full_path": obj["Key"],
                "size": file_size_format(obj["Size"]),
                "permission": get_file_permission(obj["Key"]),
                "last_modified": obj["LastModified"].strftime('%Y-%m-%d %H:%M:%S')
            }
            for obj in response['Contents']
            if obj['Key'].endswith('.jar')
        ]
    else:
        files = []

@app.route('/login')
def route_login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    try:
        response = users_table.get_item(
            Key={'username': username}
        )
        if 'Item' in response:
            stored_password = response['Item']['password']
            if stored_password == password:
                session['logged_in'] = True
                session['user_email'] = username
                return redirect(url_for('route_root'))
        return redirect(url_for('route_login', error='invalid_credentials'))
    except ClientError as e:
        return redirect(url_for('route_login', error='login_failed'))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_email', None)
    return redirect(url_for('route_login'))

@app.route('/download')
def route_donwload():
    if not session.get('logged_in'):
        return jsonify({'error': '请先登录'}), 401
    if not has_permission(session.get('user_email'), get_file_permission(request.args.get('key'))):
        return jsonify({'error': '没有权限下载该插件, 你可以联系小明购买'}), 403
    key = request.args.get('key')
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
        file_data = response['Body'].read()
        return send_file(
            BytesIO(file_data),
            download_name=key.split('/')[-1],
            mimetype='application/octet-stream',
            as_attachment=True
        )
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({'error': '下载文件时发生错误'}), 500

@app.route('/')
def route_root():
    if not session.get('logged_in'):
        return redirect(url_for('route_login'))
    update_s3_objects()
    return render_template('index.html', files=files, session=session)

if __name__ == '__main__':
    app.run(debug=True, port=80, host='0.0.0.0')
