"""SAS compliance chat from the command line (CloudShell or your laptop).

Usage:  python3 chat_cli.py            interactive
        python3 chat_cli.py "Is SC-28 satisfied?"   one question
Add --tools to see which tools the model called.
Uses your current AWS credentials; needs lambda:InvokeFunction on sas-chat.
"""
import json
import sys

import boto3

FUNCTION = "sas-chat"
lam = boto3.client("lambda", region_name="us-east-1")


def ask(question, history):
    resp = lam.invoke(FunctionName=FUNCTION,
                      Payload=json.dumps({"question": question, "history": history}).encode())
    data = json.loads(resp["Payload"].read())
    if "errorMessage" in data:
        raise RuntimeError(data["errorMessage"])
    return data


def main():
    args = [a for a in sys.argv[1:] if a != "--tools"]
    show_tools = "--tools" in sys.argv
    history = []
    if args:
        data = ask(" ".join(args), history)
        print(data["answer"])
        if show_tools:
            print("\n[tools] " + ", ".join(c["tool"] for c in data["tool_calls"]))
        return
    print("SAS compliance chat. Ask about any NIST 800-53 control. Ctrl+C to quit.\n")
    while True:
        try:
            q = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not q:
            continue
        data = ask(q, history)
        history = data["history"]
        print(f"\nsas> {data['answer']}\n")
        if show_tools:
            print("[tools] " + ", ".join(f"{c['tool']}({json.dumps(c['input'])})" for c in data["tool_calls"]) + "\n")


if __name__ == "__main__":
    main()
