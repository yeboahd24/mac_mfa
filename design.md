Context and scope

This design document focuses on implementing a Multi-Factor Authentication (MFA) system with device management and compliance features in a Django-based web application. The system aims to enhance security by adding an extra layer of authentication and controlling device access. The project includes user authentication, device recognition, MFA creation and verification, and device logout functionality.

Goals and non-goals

Goals:

Implement Multi-Factor Authentication (MFA) using Time-based One-Time Password (TOTP)

Create a device management system for user login and logout

Implement device compliance checks

Enhance security with JWT-based authentication

Support multiple authentication backends

Non-goals:

Implement biometric authentication

Develop a mobile application for MFA

Implement hardware token-based MFA

Design

System-context-diagram

```mermaid
    participant User
    participant Client
    participant Django App
    participant User Model
    participant Device Model
    participant MFA System
    participant JWT System

    User->>Client: Initiate login
    Client->>Django App: Send login request
    Django App->>User Model: Authenticate user
    User Model-->>Django App: User authenticated
    Django App->>Device Model: Check device info
    Device Model-->>Django App: Device status
    Django App->>MFA System: Request MFA verification
    MFA System-->>Django App: MFA result
    Django App->>JWT System: Generate tokens
    JWT System-->>Django App: Access and refresh tokens
    Django App-->>Client: Login response
    Client-->>User: Login result
```
APIs

The system exposes the following main API endpoints:

Login: /login/

Device Login: /device/login/

Device Compliance Login: /device/login_compliance/

MFA Creation: /mfa/create/

MFA Verification: /totp/login/<token>/

Device Logout: (Not explicitly defined in the provided code, but implied)

Data storage

The system uses Django's ORM with SQLite as the default database. Key models include:

User: Custom user model (AUTH_USER_MODEL = "user.User")

Device: Stores device information

UserDevice: Associates users with devices

RolePermission: Manages role-based access control

Code and pseudo-code

The system implements the following key components:

Custom authentication middleware (user.middleware.AuthenticationMiddleware)

JWT-based authentication with access and refresh tokens

Device information parsing using user agents

MFA creation and verification views

Device logout functionality

Degree of constraint

This design is moderately constrained by the Django framework and the existing project structure. It builds upon Django's authentication system and extends it with custom functionality for MFA and device management.

Alternatives considered

Using third-party MFA libraries:

Pro: Faster implementation, potentially more secure

Con: Less flexibility, potential compatibility issues

Implementing biometric authentication:

Pro: Enhanced security, user convenience

Con: Increased complexity, limited device support

Using a separate microservice for MFA:

Pro: Better separation of concerns, scalability

Con: Increased system complexity, potential latency

The chosen design balances security, flexibility, and ease of implementation within the existing Django project structure.
