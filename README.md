# 🔍 FindBack — Lost & Found Portal

A web-based Lost & Found Portal designed to help students report lost belongings, share found items, and connect with the people who own them.

FindBack aims to make the process of finding lost items easier, faster, and more organized within a college campus. Instead of relying only on verbal announcements or scattered messages, students can use a centralized platform to report and search for lost and found belongings.

---

## 🌐 Project Overview

FindBack provides a common platform where students can report lost items, submit details about found items, and manage claims. Teachers and administrators can help manage reports and verify claims to maintain a more reliable lost-and-found process.

The project was developed during **Parakram Hackathon at SRIMT** by Team Hack Hawk.

---

## ✨ Key Features

- 🔍 **Lost & Found Reporting** — Report lost belongings and items that have been found.
- 📝 **Item Details** — Provide relevant information to help identify belongings.
- 📋 **Report Management** — Organize and manage lost-and-found reports.
- 🤝 **Claim Management** — Allow users to claim items that belong to them.
- 👨‍🎓 **Student Portal** — Provide students with access to the lost-and-found system.
- 👨‍🏫 **Teacher Module** — Support authorized teacher-level activities.
- 🛡️ **Admin Dashboard** — Manage reports, claims, and relevant administrative actions.
- 🔐 **Authentication** — Support controlled access to portal functionality.
- 🤖 **CAPTCHA Verification** — Help distinguish human users from automated traffic.
- 📱 **Responsive Interface** — Designed for convenient use across different screen sizes.

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python | Backend application logic |
| Flask | Web application framework and routing |
| SQLite | Database for storing application records |
| Werkzeug | Password hashing and security-related utilities |
| Jinja2 | Dynamic HTML rendering |
| HTML5 | Web page structure |
| CSS3 | Styling and responsive layouts |
| JavaScript | Client-side interactions |
| Bootstrap | UI components and responsive design |
| Google reCAPTCHA | CAPTCHA-based verification, where configured |

---

## 👥 User Roles

### 🎓 Student
- Access the student portal.
- Report lost belongings.
- Submit found-item reports.
- View relevant reports and use the claim functionality.
- Track the status of their submissions where supported.

### 👨‍🏫 Teacher
- Access authorized teacher functionality.
- Assist with the management of relevant reports and claims, according to assigned permissions.

### 🛡️ Administrator
- Manage the portal and its records.
- Review reported items and claims.
- Verify information before taking appropriate action.
- Update claim or report statuses.
- Maintain the platform's administrative operations.

---

## 🔄 How FindBack Works

1. **Report an Item:** A student submits the details of a lost or found item.
2. **Browse Reports:** Users check the available reports to identify potentially matching belongings.
3. **Submit a Claim:** A user submits a claim for an item they believe belongs to them.
4. **Verification:** The authorized administrator or responsible staff member reviews the claim and supporting details.
5. **Status Update:** The authorized person updates the report or claim status after verification.
6. **Resolution:** The item can be returned to its rightful owner according to the institution's process.

*Note: Exact permissions and status transitions depend on the application's implemented rules and institutional policies.*

---

## 📂 Project Structure

The project is built around a Flask-based backend, HTML templates, static frontend assets, and a database.

A typical structure for this application may look like:

```text
FindBack/
│
├── app.py
├── requirements.txt
├── .env
├── templates/
├── static/
├── instance/
├── manage.py
└── README.md
```

*The structure above is illustrative. Keep only the files and directories that actually exist in your repository. Never commit your `.env` file or production secrets.*

---

## 🚀 Getting Started

### Prerequisites

Make sure you have:

- Python 3.12 or another version supported by your project.
- Git installed on your system.
- A code editor such as Visual Studio Code.
- The environment variables required by the application.

### 1. Clone the Repository

```bash
git clone https://github.com/codertheashish/FindBack.git
```

### 2. Open the Project Folder

```bash
cd FindBack
```

### 3. Create a Virtual Environment

**Windows:**

```bash
python -m venv venv
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables

Create a local `.env` file and configure the environment variables required by your application.

For example:

```env
SECRET_KEY=your-secret-key
```

Configure any additional database, CAPTCHA, session, or authentication settings required by the project.

**Security:** Use strong secret values, keep API credentials and passwords private, and never upload production secrets to GitHub.

### 6. Run the Application

If `app.py` exposes a Flask application named `app`, you can start it using:

```bash
python app.py
```

Alternatively, if the application is designed to run through the Flask CLI:

```bash
flask --app app run --debug
```

Open the local URL shown in your terminal, usually:

```text
http://127.0.0.1:5000
```

*Use the startup command that matches your application's actual entry point and configuration.*

---

## ☁️ Deployment

FindBack has been deployed using **PythonAnywhere**.

General deployment workflow:

1. Upload or clone the project into your hosting environment.
2. Create and configure a Python virtual environment.
3. Install the dependencies from `requirements.txt`.
4. Configure the WSGI entry point and environment variables.
5. Configure database access, session security, and CAPTCHA settings.
6. Reload the web application and test student, teacher, and administrator workflows.

Before deployment, verify that the application uses secure production settings and that confidential information is not exposed.

---

## 🔮 Future Scope

### 🏫 Integration with the College Portal

Our future goal is to integrate FindBack directly into the **existing college portal** as a dedicated Lost & Found section.

The planned integration will work as follows:

- **Dedicated Portal Section:** FindBack will be accessible as a separate section within the college's official portal.
- **Administrator-Controlled Permissions:** The college administration will control access permissions and the management of this section.
- **Visible to All Students:** The Lost & Found section will be visible to students whether or not they have previously reported a lost item or submitted a found-item report.
- **Centralized Access:** Students will be able to open the section directly from the college portal instead of visiting a separate website.
- **Simplified Student Experience:** Students can check available reports whenever they need to, even if they have never submitted a report before.
- **Improved Campus Coordination:** Centralized reporting can help students and authorized college staff coordinate the recovery of lost belongings.

The aim is to make FindBack a regular part of the college's digital ecosystem, with appropriate permissions and administrative oversight.

### 🚀 Additional Enhancements

- 🔔 Notifications when a potentially matching item is reported.
- 🖼️ Image uploads for lost and found items.
- 🔎 Advanced search and filtering.
- 📧 Email notifications for claims and status updates.
- 📊 Reports and analytics for administrators.
- 📱 Improved mobile experience.
- 🔐 Integration with college student accounts or single sign-on.
- 🏫 Support for multiple departments and campuses.

---

## 🏆 Hackathon Credits

**Event:** Parakram Hackathon, SRIMT  
**Team Name:** Hack Hawk

**Team Leader:** Ashish Kumar Prajapati

**Team Members:**
- [@Rajarshi Roop Sahani](https://github.com/RajarshiroopAI)
- [@Sonali Gupta](https://github.com/sonalicodehub)
- [@Swayam Gupta](https://github.com/swayamgupta302-crypto)

FindBack was developed as a team project during the hackathon to address the everyday challenge of recovering lost belongings in a college environment.

---

## 👨‍💻 Author & Links

**Ashish Kumar Prajapati**

- GitHub: [@codertheashish](https://github.com/codertheashish)
- LinkedIn: [@codertheashish](https://www.linkedin.com/in/codertheashish/)
- Instagram: [@codertheashish](https://www.instagram.com/codertheashish/)

---

## 🤝 Contributing

Suggestions, improvements, and contributions are welcome.

If you would like to contribute:

1. Fork this repository.
2. Create a new feature branch.
3. Make your changes and test them.
4. Submit a pull request describing your improvements.

---

## 📜 License

A license has not been specified here. Add a suitable open-source license to the repository if you intend to permit reuse and redistribution.

---

⭐ **If you like FindBack, consider giving this repository a star on GitHub!**

Built with teamwork and innovation by **Team Hack Hawk** at Parakram Hackathon, SRIMT.
