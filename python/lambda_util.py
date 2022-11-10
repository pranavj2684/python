import boto3,json

lambda_client = boto3.client('lambda')

response = lambda_client.invoke(FunctionName='mys3lambda')

print(response)