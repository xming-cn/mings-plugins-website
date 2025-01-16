import boto3
import sys

def generate_password(length=12):
    import random
    import string
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def add_user(username, password, permissions=None):
    dynamodb = boto3.resource('dynamodb')
    users_table = dynamodb.Table('users')
    
    response = users_table.get_item(
        Key={'username': username}
    )
    if 'Item' in response:
        print(f"Error: User '{username}' already exists")
        return False
    
    item = {
        'username': username,
        'password': password
    }
    if permissions:
        item['permission'] = permissions
        
    print(item)
    users_table.put_item(Item=item)
    print()
    print(f"Successfully added user '{username}'")
    print()
    print('username', username)
    print('password', password)
    print()
    with open('accounts.txt', 'a') as f:
        f.write(f'{username},{password}\n')
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python add_account.py <username> [password] [permission1,permission2,...]")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else generate_password()
    permissions = sys.argv[3].split(',') if len(sys.argv) > 3 else None
    
    add_user(username, password, permissions)