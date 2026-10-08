# CampusPulse

A college student-success workspace built with Flask and SQLite. Different signed-in roles receive different data scopes.

## Roles and access

- **Dean:** college-wide reports, announcements, staff accounts, student accounts and lab oversight.
- **HOD:** department roster, attendance, progress updates, follow-ups and department announcements.
- **Professor:** assigned student roster, attendance, grades, follow-ups and lab booking requests.
- **Lab Assistant:** equipment inventory, maintenance status and booking approvals.
- **Student:** only their own academic progress and college announcements.

There are no pre-made demo accounts. The first Dean account is created once at `/setup` using the private `INITIAL_DEAN_KEY`. The Dean then creates staff and student accounts from the dashboard. Login requires email, password and the matching role.

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
export SECRET_KEY="use-a-long-random-value"
export INITIAL_DEAN_KEY="choose-a-private-first-setup-key"
python3 app.py
```

Open `http://127.0.0.1:5000/setup`, create the Dean account, then sign in at `/login`.

## Render setup

This repository includes `render.yaml` for a Render Blueprint deployment. Set the prompted `INITIAL_DEAN_KEY` to a private, hard-to-guess value. If you already have a manually configured Render Web Service, add both `INITIAL_DEAN_KEY` and a long random `SECRET_KEY` under **Environment** before using `/setup`. Keep both values private. The one-time migration from the old demo version removes the seeded demo users, sample students and their follow-up records; make a database backup first if you have entered any records you need to keep.

## Features

- Password-hashed accounts, role validation and account enable/disable controls
- Role-scoped student records and dashboards
- Attendance register with date-based updates
- Academic progress editing and downloadable CSV reports
- Department and college announcements
- Student support follow-up tracker
- Lab equipment inventory, maintenance status and time-slot booking workflow
- Responsive layout for desktop and mobile

## Data and privacy

The application has no seeded people, student records or demo credentials. Data is stored in SQLite. Render's default filesystem is temporary, so this prototype is for judging with non-sensitive information only. Before using real college records, move the data to a persistent managed database, add backups and complete a security review. Support indicators are simple guidance signals, not validated predictions.
