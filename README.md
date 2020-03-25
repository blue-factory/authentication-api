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
message Auth {
	string id = 1;
	string user_id = 2;
	string token = 3;
	bool blacklist = 4;
  string kind = 5;

	int64 created_at = 6;
	int64 updated_at = 7;
}

message AuthToken {
  int64 iat = 1;
  int64 exp = 2;
  string user_id = 3;
}

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

`PORT`: define auth service port.

`HOST`: define auth service host.

`POSTGRES_DSN`: define postgres database connection DSN.

`JWT_SECRET`: define secret used for generate tokens.

## Commands (Development)

`make build`: build restaurants service for osx.

`make linux`: build restaurants service for linux os.

`make docker .`: build docker.

`make compose`: start docker-docker.

`make stop`: stop docker-docker.

`make run`: run auth service.

`docker run -it -p 5010:5010 auth-api`: run docker.
