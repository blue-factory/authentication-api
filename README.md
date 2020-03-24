# Auth-API

Microservice implemented in Golang that allows authenticating access to the backend through a JWT token. On the other hand, it manages user signup and login.

## Table

```
   Column   |           Type           | Collation | Nullable |      Default
------------+--------------------------+-----------+----------+-------------------
 id         | uuid                     |           | not null | gen_random_uuid()
 user_id    | text                     |           | not null |
 token      | text                     |           | not null |
 backlist   | boolean                  |           | not null | false
 kind       | text                     |           | not null |
 created_at | timestamp with time zone |           |          | now()
 updated_at | timestamp with time zone |           |          | now()
 deleted_at | timestamp with time zone |           |          |
Indexes:
    "auth_pkey" PRIMARY KEY, btree (id)
Triggers:
    update_auth_update_at BEFORE UPDATE ON auth FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column()
```

## GRPC Service

```go
service AuthService {
  rpc GetByToken(AuthGetByTokenRequest) returns (AuthGetByTokenResponse) {}
  rpc Login(AuthLoginRequest) returns (AuthLoginResponse) {}
  rpc Signup(AuthSignupRequest) returns (AuthSignupResponse) {}
  rpc VerifyToken(AuthVerifyTokenRequest) returns (AuthVerifyTokenResponse) {}
  rpc Logout(AuthLogoutRequest) returns (AuthLogoutResponse) {}
  rpc ForgotPassword(AuthForgotPasswordRequest) returns (AuthForgotPasswordResponse) {}
  rpc RecoverPassword(AuthRecoverPasswordRequest) returns (AuthRecoverPasswordResponse) {}
}
```

## Environments Values

`PORT`: define users service port.

`HOST`: define users service host.

`POSTGRES_DSN`: define postgres database connection DSN.

## Commands (Development)

`make build`: build restaurants service for osx.

`make linux`: build restaurants service for linux os.

`make docker .`: build docker.

`docker run -it -p 5030:5030 tenpo-auth-api`: run docker.

`PORT=<port> JWT_SECRET=<jwt_secret> USERS_HOST=<users_host> USERS_PORT=<users_port> make r`: run tenpo auth service.
