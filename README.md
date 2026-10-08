# CampusPulse — role-based student success demo

A local Flask + SQLite hackathon prototype. Demo records are synthetic. Professor, HOD and Dean accounts receive different data scopes.

## Run on macOS

Open this folder in VS Code, choose **Terminal → New Terminal**, then run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000` in a browser. Keep the terminal open while using the app.

## Demo accounts

| Role | Email | Password | Access |
|---|---|---|---|
| Professor | `prof@campuspulse.demo` | `prof123` | CSE students assigned to that professor |
| Professor | `itprof@campuspulse.demo` | `itprof123` | IT students assigned to that professor |
| HOD | `hod@campuspulse.demo` | `hod123` | All CSE students |
| HOD | `ithod@campuspulse.demo` | `ithod123` | All IT students |
| Dean | `dean@campuspulse.demo` | `dean123` | Students across both departments |

HOD and Dean can add student records; professors can add follow-up notes only for students in their assigned roster. Each account is checked by the backend on every data request. Login passwords are stored as hashes. The demo student records are fake examples.

## Included

- SQLite persistence and seeded demo cohort
- Role-scoped student roster and cohort metrics
- Attendance, marks, assignments, quiz scores, risk reasons and weak-subject hints
- Support follow-up actions
- Responsive layout for phones and desktop
- Form validation and duplicate-email handling

The risk status is a transparent heuristic based on the average of four scores. It is a demo support signal, not a validated prediction of student outcomes. This project is for local judging with sample data; it has no account administration, password reset, or production security review. Do not use real student data in a public deployment.
