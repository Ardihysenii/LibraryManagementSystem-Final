📘 BookCore | Ultimate Library Management System

Thank you for choosing BookCore — the professional-grade solution for managing your library efficiently. Built with clean code, modern architecture, and user-focused design, BookCore delivers a secure, responsive, and lightning-fast experience for administrators and library users alike.

Welcome to the next level of library management.

🚀 Overview

BookCore is designed to simplify complex library operations while providing a polished and intuitive interface. With a high-performance stack and scalable architecture, it ensures data integrity, security, and ease of use.

🔑 Key Features
1. Authentication & Access Control

Secure Login & Sign-Up: Quick, reliable, and safe entry points.

Role-Based Access: Built-in logic to distinguish administrators from standard users.

Session Security: Protects sensitive library data from unauthorized access.

2. Dashboard (Command Center)

Live Catalog Management: Add, edit, or remove books, authors, and genres in real time.

Smart Lending Tracker: Monitor borrowing activity, including who has which book and due dates.

Interactive Insights: Visual indicators provide a quick view of library health and inventory status.

3. Core Functionality

Automated Notifications: Alerts for overdue or expiring items.

Responsive Design: Works seamlessly on desktops, tablets, and smartphones.

High-Performance Logic: Built on Spring Boot for industrial-strength backend processing.

🛠 Tech Stack

Backend: Spring Boot (Java) – secure, scalable, and production-ready.

Templating: Thymeleaf – dynamic, server-side rendering for fast performance.

Frontend: Bootstrap 5 + Custom CSS3 – modern and polished UI.

Database: SQL Server – optimized for integrity, speed, and reliability.

⚙️ Setup & Installation

BookCore is containerized using Docker for simple deployment. Follow these steps:

Clone the repository

git clone <repo-url>
cd BookCore


Create .env file based on .env.example

DB_USERNAME=sa
DB_PASSWORD=YourStrongPassword
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-app-password


Build & Run with Docker Compose

docker-compose up --build


Access the App

Open a browser and go to: http://localhost:8080

Default admin credentials:

Username: admin

Password: admin123

⚠️ Change default credentials immediately after first login.

📦 Project Structure
BookCore/
├── src/                 # Source code
├── target/              # Built JAR file
├── docker-compose.yml   # Docker orchestration
├── Dockerfile           # Application container
├── database/            # Schema & sample data SQL scripts
├── screenshots/         # UI snapshots for reference
└── README.md

✅ Best Practices

Use environment variables for sensitive information (DB_USERNAME, DB_PASSWORD, MAIL_USERNAME, MAIL_PASSWORD).

Database changes should be made via migration scripts or admin dashboard.

Maintain backups of your SQL Server database volume (especially in production).

📈 Why BookCore?

Enterprise-grade architecture ready for scaling.

Clean, maintainable code suitable for development or customization.

Rapid deployment with Docker and clear documentation.

Professional-grade UI & UX for both admins and end-users.

This version makes the README:

Polished & professional for buyers or GitHub presentation

Clear instructions for setup & deployment

Enterprise-level impression

Safe to share, no sensitive credentials included