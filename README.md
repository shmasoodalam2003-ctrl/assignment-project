#  Cybersecurity Assignment – OWASP Juice Shop

##  Overview
This repository contains my work on the **OWASP Juice Shop** project as part of my cybersecurity assignment.  
Juice Shop is a deliberately insecure web application used to practice identifying and fixing common web vulnerabilities.  

The assignment was divided into 3 phases:  
1. **Security Assessment** (finding vulnerabilities)  
2. **Security Fixes** (implementing mitigations)  
3. **Advanced Security & Reporting** (logging, penetration testing, and documentation)  

---

##  Setup & Installation

### 1. Clone Juice Shop Repository
```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop

Install Dependencies:
npm install

Start the Appliciation:
npm start

By default, the app runs on  http://localhost:3000

 Assignment Work
 Week 1: Security Assessment

 I explored the app and tested the following pages:
 **Signup / Login
 **Product Reviews
 **User Profile

 Vulnerabilities Found:

 **Cross-Site Scripting (XSS)
 **Injected <script>alert('XSS')</script> in product review field.
 **Malicious script executed in the browser.
 **SQL Injection

Bypassed login using:

 admin' OR '1'='1
 
Insecure Password Storage:

 **Passwords stored in plaintext in the database.

Missing Security Headers:

 **No protection against clickjacking, MIME sniffing, etc.

Weak Authentication:

 **Session tokens not securely validated.

Week 2: Security Fixes

I modified the application with basic security improvements:

**Input Validation & Sanitization:
const validator = require('validator');
if (!validator.isEmail(email)) {
  return res.status(400).send("Invalid email");
}
**Password Hashing with bcrypt:
const bcrypt = require('bcrypt');
const hashedPassword = await bcrypt.hash(password, 10);


**JWT Authentication:
const jwt = require('jsonwebtoken');
const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
res.send({ token });


**Helmet.js for Security Headers:
const helmet = require('helmet');
app.use(helmet());

Week 3: Advanced Security & Reporting

¬Penetration Testing with Nmap & browser dev tools.

**Logging with Winston to track suspicious login attempts:
const winston = require('winston');
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});
logger.info("Application started");


**Security Checklist Implemented:

 Input validation & sanitization

 Passwords hashed & salted

 HTTPS recommended

 Helmet middleware for secure headers

 Logging enabled

**Results:

XSS attacks blocked by sanitizing user inputs.

SQL Injection no longer possible due to input validation.

Passwords now securely hashed before storage.

Session tokens handled with JWT for authentication.

Security headers improved via Helmet.

Logging system in place for suspicious activity.

**Deliverables

Recorded Video: Screen recording showing vulnerabilities & fixes.

GitHub Repository: Contains modified Juice Shop code, configurations, and this README.

Final Report: Written summary of vulnerabilities and applied fixes.

**Author

Huda Masood

GitHub: @YourUsername

Assignment Deadline: 5th Sept, 2025


---


