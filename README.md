# adaptive-callback-decision-engine
A research project exploring how context-aware decision engines could be used to model delayed, condition-based activity in long-dwell intrusion scenarios. The goal is to simulate how an agent might weigh environmental signals, organizational changes, and operational noise to study detection challenges and improve defensive monitoring.


### Test Curl Commands to Flask Decision Engine:

Keep Sleeping Decision: curl -X POST http://127.0.0.1:8000/webhook -H "Content-Type: application/json" -d "{\"kind\":\"test_event\",\"actor\":\"alice\",\"target\":\"lab\",\"severity\":1}"

Keep Sleeping Decision: curl -X POST http://127.0.0.1:8000/webhook -H "Content-Type: application/json" -d "{\"kind\":\"signin_failed\",\"actor\":\"bob\",\"target\":\"vpn\",\"severity\":2}"

Run Decision: curl -X POST http://127.0.0.1:8000/webhook -H "Content-Type: application/json" -d "{\"kind\":\"org_change\",\"actor\":\"hr_system\",\"target\":\"company_wide_restructure\",\"severity\":3,\"details\":\"Large-scale reorganization announced with multiple department moves, leadership changes, and bulk user/group updates.\"}"
