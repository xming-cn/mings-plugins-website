import time
import asyncio
import aioboto3
from io import BytesIO
from botocore.exceptions import ClientError
from quart import Quart, render_template, send_file, request, session, redirect, url_for, jsonify

S3_BUCKET = "mings-plugins"

aio_session = aioboto3.Session()

app = Quart(__name__)

@app.context_processor
async def inject_session():
    return dict(session=session)

def file_size_format(size):
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    i = 0
    while size >= 1024 and i < len(units)-1:
        size /= 1024
        i += 1
    return f"{size:.2f} {units[i]}"

async def get_file_permission(file_path: str):
    if file_path.startswith('SCConflict/'):
        return 'SCConflict'
    elif file_path.startswith('SCConflict-Free/'):
        return '免费'
    elif file_path.startswith('SBPlaceholder2/'):
        return '免费'

async def has_permission(username: str, permission: str):
    if permission == '免费':
        return True
    if not username:
        return False
    try:
        async with aio_session.client('dynamodb') as dynamodb_client:
            response = await dynamodb_client.query(
                TableName='users',
                KeyConditionExpression='username = :username',
                ExpressionAttributeValues={
                    ':username': {'S': username}
                }
            )
        if 'Items' not in response:
            return False
        if 'permission' not in response['Items'][0]:
            return False
        user_permissions = response['Items'][0].get('permission', '')
        print('user_permissions: ' + user_permissions)
        return permission in user_permissions
    except:
        return False

files = []
update_time = None

async def init():
    global files, update_time
    app.secret_key = await get_secret_key()
    await update_s3_objects()

async def get_secret_key():
    secret_name = '/ming-plugins-website/secret_key'
    async with aio_session.client('ssm') as ssm_client:
        response = await ssm_client.get_parameter(Name=secret_name, WithDecryption=True)
    return response['Parameter']['Value']

async def update_s3_objects():
    global files, update_time
    if update_time and time.time() - update_time < 60:
        return
    update_time = time.time()
    
    try:
        async with aio_session.client('s3') as s3_client:
            response = await s3_client.list_objects_v2(Bucket=S3_BUCKET)
    except Exception as e:
        print(e)
        return
    if 'Contents' in response:
        files = [
            {
                'key': obj['Key'].split('/')[-1],
                'full_path': obj['Key'],
                'size': file_size_format(obj['Size']),
                'last_modified': obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S'),
                'permission': await get_file_permission(obj['Key'])
            }
            for obj in response['Contents']
            if obj['Key'].endswith('.jar')
        ]
        files.sort(key=lambda x: x['key'])

@app.route('/login')
async def route_login():
    return await render_template('login.html')

@app.route('/login', methods=['POST'])
async def login():
    form = await request.form
    username = form.get('username')
    password = form.get('password')
    
    try:
        async with aio_session.client('dynamodb') as dynamodb_client:
            response = await dynamodb_client.query(
                TableName='users',
                KeyConditionExpression='username = :username',
                ExpressionAttributeValues={
                    ':username': {'S': username}
                }
            )
        if 'Items' in response:
            stored_password = response['Items'][0]['password']['S']
            if stored_password == password:
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('route_root'))
    except ClientError as e:
        print(e.response['Error']['Message'])
    
    return redirect(url_for('route_login'))

@app.route('/logout')
async def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('route_root'))

@app.route('/download')
async def route_donwload():
    if not session.get('logged_in'):
        return jsonify({'error': '请先登录'}), 401
    if not await has_permission(session.get('username'), await get_file_permission(request.args.get('key'))):
        return jsonify({'error': '没有权限下载该插件, 你可以联系小明购买'}), 403
    key = request.args.get('key')
    if key == None:
        return jsonify({'error': '需要指定一个有效的文件键'}), 500
    try:
        async with aio_session.client('s3') as s3_client:
            response = await s3_client.get_object(Bucket=S3_BUCKET, Key=key)
        file_data = await response['Body'].read()
        return await send_file(
            BytesIO(file_data),
            mimetype='application/octet-stream',
            attachment_filename=key.split('/')[-1],
            as_attachment=True
        )
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({'error': '下载文件时发生错误'}), 500

@app.route('/')
async def route_root():
    await update_s3_objects()
    return await render_template('index.html', files=files, session=session)

async def main():
    print('init')
    await init()
    print('update_s3_objects')
    await update_s3_objects()
    print('app.run')
    server = app.run_task(host='0.0.0.0', port=80)
    asyncio.create_task(server)
    while True:
        await asyncio.sleep(0.1)

if __name__ == '__main__':
    asyncio.run(main())
