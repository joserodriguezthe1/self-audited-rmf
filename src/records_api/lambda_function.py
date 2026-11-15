"""SAS records API: the workload inside the boundary that the assessment evaluates.

GET  /records?id=<record_id>   read one record
POST /records {"title": "..."} create a record
Both routes require IAM (SigV4) authorization at API Gateway.
"""
import json, os, uuid, boto3

table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])

def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")

    if method == "POST":
        body = json.loads(event.get("body") or "{}")
        item = {"record_id": str(uuid.uuid4()), "title": str(body.get("title", ""))[:200]}
        table.put_item(Item=item)
        return {"statusCode": 201, "body": json.dumps(item)}

    rid = (event.get("queryStringParameters") or {}).get("id")
    if not rid:
        return {"statusCode": 400, "body": json.dumps({"error": "id required"})}
    resp = table.get_item(Key={"record_id": rid})
    if "Item" not in resp:
        return {"statusCode": 404, "body": json.dumps({"error": "not found"})}
    return {"statusCode": 200, "body": json.dumps(resp["Item"])}
