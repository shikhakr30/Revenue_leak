# RevenueLeak AI — AI Revenue Recovery

A portfolio-ready Flask and MySQL application that detects preventable revenue leakage, explains why a transaction was flagged, and tracks the money recovered.

## Complete feature set

- Dark enterprise landing page and responsive application theme
- Secure signup and sign-in, password hashing, CSRF protection and session expiry
- New-account approval workflow with company profiles and administrator role assignment
- Admin, Analyst and Viewer role-based permissions
- Transaction create, edit, delete, search, date filtering and CSV export
- Atomic bulk CSV import with a downloadable template and duplicate protection
- Explainable hybrid detection engine:
  - underbilling
  - unbilled active service
  - overdue payment
  - excessive discount
  - unsupervised peer-anomaly detection using robust Median/MAD scoring
- Risk score, severity, estimated loss and plain-language explanation
- Recovery plans with owner, priority, action, target date, status and recovered amount
- Dashboard KPIs, recovery queue and live MySQL totals
- Six-month collection analytics, leakage categories and severity distribution
- Filterable audit report with CSV export
- Team account management and activity audit trail
- One-click portfolio demo dataset
- Automated integration tests

The anomaly model runs locally. It does not require an API key or paid AI service.

## Install on Windows

1. Start **MySQL** in XAMPP.
2. Double-click **`START_WINDOWS.bat`**. It creates the virtual environment, installs requirements and starts the site.
3. Open `http://127.0.0.1:5000` in Chrome.

The application creates the `revenueleak_ai` MySQL database and missing tables automatically. Existing data is preserved. If you already have a `.env` file, the starter keeps it unchanged.

### Manual start (optional)

Open the project folder in VS Code and run:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe app.py
   ```

Then open `http://127.0.0.1:5000`.

## First login

- Email: `admin@revenueleak.ai`
- Password: `Admin@123`

After signing in, open **Profile** and change the password. You can replace the defaults before first run using `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`.

## Fast portfolio demonstration

1. Sign in as Admin.
2. Open **Team settings** using the gear icon.
3. Select **Load demo data**.
4. Open **Alerts** to show explainable AI results.
5. Create a recovery plan for one alert.
6. Open **Analytics** and **Reports** to demonstrate business impact.

## Roles

| Role | Permissions |
| --- | --- |
| Admin | Full access, deletion, users and demo data |
| Analyst | Add/import/edit data, run scans and manage recoveries |
| Viewer | Read-only dashboards, transactions, alerts and reports |

## New-user account flow

1. A user selects **Create account** and enters their name, company, email and password.
2. The new account is stored as **Pending** and cannot access financial data.
3. An Admin opens **Team settings**, selects a role and approves the request.
4. The approved user can sign in and update their profile or password.

## Run automated tests

The test suite uses a temporary in-memory SQLite database and does not modify MySQL.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Deployment readiness

`wsgi.py`, `Procfile`, environment-based configuration and `/health` are included for deployment on a WSGI-compatible host. Set `DATABASE_URL`, use a strong `SECRET_KEY`, change the admin password, set `FLASK_DEBUG=0`, and set `COOKIE_SECURE=1` when the site is served over HTTPS.

## Project structure

```text
app.py                 Routes, security and application services
models.py              Database models
services/detector.py   Explainable rules and anomaly model
templates/             Flask/Jinja pages
static/css/style.css   Complete dark interface theme
tests/test_app.py      Integration tests
config.py              Environment-driven configuration
```
