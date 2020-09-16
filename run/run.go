package run

import (
	"fmt"
	"log"
	"net"

	// Used by psql driver
	_ "github.com/lib/pq"
	auth "github.com/microapis/authentication-api"
	"github.com/microapis/authentication-api/database"
	pb "github.com/microapis/authentication-api/proto"
	"github.com/microapis/authentication-api/rpc"

	usersclient "github.com/microapis/users-api/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Run ...
func Run(address string, postgresDSN string, usersAddress string, mailingTmpl *auth.MailingTemplates) {
	pgSvc, err := database.NewPostgres(postgresDSN)
	if err != nil {
		log.Fatalf("Failed connect to postgres: %v", err)
	}

	uc, err := usersclient.New(usersAddress)
	if err != nil {
		log.Fatalf(err.Error())
	}

	srv := grpc.NewServer()
	svc := rpc.New(pgSvc, uc, mailingTmpl)

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
