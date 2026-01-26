Cloud Bank – Flask Web Application

Cloud Bank is a role-based banking web application developed using Flask.  
The project is designed to run locally as well as on AWS using managed cloud services.

Features

Customer

- Secure signup & login
- Deposit, withdraw, and transfer funds
- Transaction history with search
- CSV export of transactions
- Dashboard with balance & activity summary

Staff

- Staff login with invite code
- Customer analytics & insights
- Transaction monitoring
- Alert management (AML / large transactions)
- Compliance overview
- Report generation & CSV export

Tech Stack

- Backend: Python (Flask)
- Frontend: HTML, CSS
- Authentication: Werkzeug password hashing
- Local Storage: In-memory Python dictionaries
- Cloud (AWS):
  - DynamoDB (data storage)
  - SNS (notifications)
  - EC2 (deployment)
  - IAM (role-based access)

