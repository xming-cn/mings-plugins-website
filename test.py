import boto3
ssm_client = boto3.client('ssm')

secret_name = '/ming-plugins-website/secret_key'
secret = ssm_client.get_parameter(Name=secret_name, WithDecryption=True)
secret = secret['Parameter']['Value']
print(secret)

