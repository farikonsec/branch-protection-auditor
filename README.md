# Github Organization Branch Protection Auditor

This project automates the audit of **branch protection settings** across all repositories in a GitHub organization. It helps ensure security policies like mandatory pull request reviews, status checks, and signed commits are enforced consistently.

---

## 📌 What It Does

- Uses a GitHub App for secure, scoped authentication.
- Scans all repositories in a GitHub organization.
- Checks branch protection settings on default branches.
- Outputs findings to a CSV file.
- Uploads the CSV as a GitHub Actions artifact for easy download.

---

## ⚙️ How It Works

1. The Go script (`main.go`) authenticates using a GitHub App and lists repos in the org.
2. For each repo, it checks the default branch’s protection configuration.
3. Results are saved to `branch_protection_report.csv`.
4. A GitHub Actions workflow runs the script and uploads the report as an artifact.

---

## 🔐 Why a GitHub App?

- Provides secure, minimal permissions.
- Supports org-wide auditing without personal tokens.
- Limits the blast radius of credentials.

---

## 🚀 Prerequisites

✅ A GitHub organization (e.g., `nanasec`)  
✅ Admin access in the organization  
✅ A GitHub App with:
  - Repository administration (read-only)
  - Metadata (read-only, default)
  - Installed **on the organization**  
✅ A repo to run this audit, with GitHub Actions enabled  
✅ Three secrets created in the repo’s **Settings → Secrets → Actions**:
  - `APP_ID`
  - `INSTALLATION_ID`
  - `PRIVATE_KEY` (your GitHub App private key)

---

## 📥 Setup Instructions

### 1️⃣ Create and Install the GitHub App

- Create a GitHub App with permissions:
  - Repository administration → Read-only
  - Metadata → Read-only (default)
- Install the app on your organization, either on all or selected repositories.
- After install, GitHub redirects to:
  https://github.com/organizations/YOUR_ORG/settings/installations/INSTALLATION_ID

**  Copy the `INSTALLATION_ID` from this URL.**

### 2️⃣ Store App Credentials in Repo Secrets

In your repo where the audit runs:
- Go to **Settings → Secrets → Actions**.
- Add:
- `APP_ID`: App ID from your app settings.
- `INSTALLATION_ID`: the installation ID you copied.
- `PRIVATE_KEY`: your GitHub App private key as a multiline secret.

---

## 📂 Folder Structure

├── main.go                  # Go script for auditing
└── .github
└── workflows
└── branch-protection-audit.yml  # Workflow to run the audit


---

## ▶️ How to Run the Audit

1. Navigate to your repo on GitHub.
2. Open the **Actions** tab.
3. Select the `Branch Protection Audit` workflow.
4. Click **Run workflow** → confirm → **Run workflow**.
5. After it completes, download the `branch-protection-report.csv` artifact from the workflow summary.

---

## 📝 What You’ll Get

The audit produces `branch_protection_report.csv` listing, for each repo:
- Repository name
- Require PR before merge
- Required number of approvals
- Status checks configuration
- Enforce admins, signed commits, conversation resolution, force pushes, deletions, etc.

---

## 🔒 App Permissions

- Repository Administration: Read-only
- Metadata: Read-only (default)

---

## ✅ Best Practices

- Periodically rotate the App’s private key.
- Regularly review and prune App permissions.
- Archive CSV reports in secure long-term storage for compliance.
- Extend this script to open issues on non-compliant repos or feed data into dashboards.

---

## 📈 Enhancements to Consider

- Integrate with Slack or email for compliance alerts.
- Fail the workflow on non-compliance to enforce policies.
- Store reports in S3 and visualize trends over time with Grafana.
- Add thresholds or policy-as-code enforcement.

---

## 🙋 Need Help?

Open an issue in this repo or contact me.
