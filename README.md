# <p align="center">Auth-Service</p>

A concise and robust authentication service designed for straightforward integration into applications that require a fundamental user authentication system, without the overhead of larger solutions like Supabase or Auth0. This service provides core functionalities for user management and secure JWT-based token generation using Go, Postgres, and Redis.

## 🧐 Features
- **User Authentication & Management**: Securely register new users, authenticate them, and perform full CRUD operations on user profiles.
- **Secure Token Generation**: Generates short-lived access and long-lived refresh tokens using **ECDSA (ES256)** for strong security.
- **Token Invalidation**: Utilizes a **Redis-based blacklist** to immediately invalidate tokens upon logout, preventing reuse.
- **Public Key Distribution**: Standard `/.well-known/jwks.json` endpoint for clients to fetch public keys and verify JWT signatures.
- **Health & Logging**: Includes a `/health` endpoint for monitoring and structured, correlation-ID-tagged logging for traceable requests.

## 🛠️ Install Dependencies
Before running the service, ensure you have Go, Podman (or Docker), and `openssl` installed.

1.  **Go Modules:**
    ```bash
    go mod tidy
    ```
2.  **Generate ECDSA Keys:**
    -   **Private Key:**
        ```bash
        openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out jwt_private_key_pkcs8.pem
        ```
    -   **Public Key:**
        ```bash
        openssl pkey -in jwt_private_key_pkcs8.pem -pubout -out jwt_public_key.pem
        ```

## 🧑🏻‍💻 Usage
1.  **Configuration**
    Create a `.env` file from the example and customize the variables:
    ```bash
    cp .env.example .env
    ```

2.  **Run the Service**
    Start the entire service stack using `docker-compose`:
    ```bash
    docker-compose up --build
    ```
    The API will be available at `http://localhost:8080` (or your configured port). For detailed endpoint information, view the **Swagger Documentation** available at `http://localhost:8080/swagger/index.html` once the service is running.

## 🛠️ Tech Stack
- [Go](https://go.dev/)
- [Gin Gonic](https://gin-gonic.com)
- [PostgreSQL](https://www.postgresql.org/)
- [Redis](https://redis.io/)
- [Sqlc](https://sqlc.dev/)
- [golang-jwt/jwt/v5](https://pkg.go.dev/github.com/golang-jwt/jwt/v5)
- [Bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
- [Podman / Docker](https://podman.io/)

## 🍰 Contributing
Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

Before contributing, please read the project's code of conduct and contributing guidelines.

## 🙇 Author
#### Aurélien Aoustin
- Github: [@Sif3r](https://github.com/Sif3r)

## ➤ License
Distributed under the GNU General Public License v3. See `LICENSE` for more information.
