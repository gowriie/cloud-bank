import os
import boto3
from moto import mock_aws

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

os.environ["USERS_TABLE_NAME"] = "CloudBankUsers"
os.environ["TX_TABLE_NAME"] = "CloudBankTransactions"
os.environ["ALERTS_TABLE_NAME"] = "CloudBankAlerts"

os.environ["SNS_TOPIC_ARN"] = ""

mock = mock_aws()
mock.start()

# Import AFTER mock starts
from app_aws import app
import app_aws

def setup_infrastructure():
    print(">>> Creating Mock DynamoDB Tables...")

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

    # Users table: PK = user_id (String)
    dynamodb.create_table(
        TableName=os.environ["USERS_TABLE_NAME"],
        KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )

    # Transactions table: PK = tx_id (String)
    dynamodb.create_table(
        TableName=os.environ["TX_TABLE_NAME"],
        KeySchema=[{"AttributeName": "tx_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "tx_id", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )

    # Alerts table: PK = alert_id (String)
    dynamodb.create_table(
        TableName=os.environ["ALERTS_TABLE_NAME"],
        KeySchema=[{"AttributeName": "alert_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "alert_id", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )

    print(">>> Mock Environment Ready.")

if __name__ == "__main__":
    try:
        setup_infrastructure()
        print("\n>>> Running Flask at http://127.0.0.1:5000")
        app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
    finally:
        mock.stop()