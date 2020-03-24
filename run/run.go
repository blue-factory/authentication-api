package run

import (
	"fmt"
	"log"
	"net"

	_ "github.com/lib/pq"
	"github.com/microapis/auth-api/database"
	pb "github.com/microapis/auth-api/proto"
	authSvc "github.com/microapis/auth-api/rpc/auth"

	u "github.com/microapis/users-api/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Run ...
func Run(address string, postgresDSN string, usersAddress string) {
	pgSvc, err := database.NewPostgres(postgresDSN)
	if err != nil {
		log.Fatalf("Failed connect to postgres: %v", err)
	}

	uc := u.New(usersAddress)
	srv := grpc.NewServer()
	svc := authSvc.New(pgSvc, uc)

	pb.RegisterAuthServiceServer(srv, svc)
	reflection.Register(srv)

	log.Println("Starting auth service...")

	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to list: %v", err)
	}

	log.Println(fmt.Sprintf("Auth service running, Listening on: %v", address))

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("Fatal to serve: %v", err)
	}
}
