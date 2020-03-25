#
# SO variables
#
# DOCKER_USER
# DOCKER_PASS
#

#
# Internal variables
#
VERSION=0.0.1
NAME=auth
SVC=$(NAME)-api
BIN_PATH=$(PWD)/bin
BIN=$(BIN_PATH)/$(SVC)
REGISTRY_URL=$(DOCKER_USER)

HOST=localhost
PORT=5010
POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

JWT_SECRET=mega-secret
USERS_HOST=localhost
USERS_PORT=5020

clean c:
	@echo "[clean] Cleaning bin folder..."
	@rm -rf bin/

run r:
	@echo "[running] Running service..."
	@HOST=$(HOST) \
	 PORT=$(PORT) \
	 POSTGRES_DSN=$(POSTGRES_DSN) \
	 JWT_SECRET=$(JWT_SECRET) \
	 USERS_HOST=$(USERS_HOST) \
	 USERS_PORT=$(USERS_PORT) \
	 go run cmd/$(NAME)/main.go

build b: proto
	@echo "[build] Building service..."
	@cd cmd/$(NAME) && go build -o $(BIN)

linux l:
	@echo "[build-linux] Building service..."
	@cd cmd/$(NAME) && GOOS=linux GOARCH=amd64 go build -o $(BIN)

add-migration am: 
	@echo "[add-migration] Adding migration"
	@goose -dir "./database/migrations" create $(name) sql

migrations m:
	@echo "[migrations] Runing migrations..."
	@cd database/migrations && goose postgres $(DSN) up

docker d:
	@echo "[docker] Building image..."
	@docker build -t $(SVC):$(VERSION) .
	
docker-login dl:
	@echo "[docker] Login to docker..."
	@docker login -u $(DOCKER_USER) -p $(DOCKER_PASS)

push p: linux docker docker-login
	@echo "[docker] pushing $(REGISTRY_URL)/$(SVC):$(VERSION)"
	@docker tag $(SVC):$(VERSION) $(REGISTRY_URL)/$(SVC):$(VERSION)
	@docker push $(REGISTRY_URL)/$(SVC):$(VERSION)

compose co:
	@echo "[docker-compose] Running docker-compose..."
	@docker-compose build
	@docker-compose up

stop s: 
	@echo "[docker-compose] Stopping docker-compose..."
	@docker-compose down

clean-proto cp:
	@echo "[clean-proto] Cleaning proto files..."
	@rm -rf proto/*.pb.go || true

proto pro: clean-proto
	@echo "[proto] Generating proto file..."
	@protoc -I proto -I $(GOPATH)/src --go_out=plugins=grpc:./proto ./proto/*.proto 

test t:
	@echo "[test] Testing $(NAME)..."
	@HOST=$(HOST) \
	 PORT=$(PORT) \
	 POSTGRES_DSN=$(POSTGRES_DSN) \
	 JWT_SECRET=$(JWT_SECRET) \
	 USERS_HOST=$(USERS_HOST) \
	 USERS_PORT=$(USERS_PORT) \
	 go test -count=1 -v ./client/$(NAME)_test.go

.PHONY: clean c run r build b linux l add-migration am migrations m docker d docker-login dl push p compose co stop s clean-proto cp proto pro test t