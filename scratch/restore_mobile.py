import json

transcript_path = "/home/jonatas/.gemini/antigravity-ide/brain/e419cf74-1504-42af-8865-0809f4416499/.system_generated/logs/transcript.jsonl"

with open(transcript_path, "r", encoding="utf-8") as f:
    for line in f:
        data = json.loads(line)
        if data.get("step_index") == 108:
            for tc in data.get("tool_calls", []):
                if tc.get("name") == "write_to_file":
                    code = tc["args"]["CodeContent"]
                    print(f"Type: {type(code)}")
                    print(f"Length: {len(code)}")
                    print(f"Starts with double quote? {code.startswith(chr(34))}")
                    print(f"Ends with double quote? {code.endswith(chr(34))}")
                    print(f"First 50 chars: {repr(code[:50])}")
                    exit(0)
