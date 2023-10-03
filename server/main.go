package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/eduardonunesp/bls-server/commons/bls"
	"github.com/eduardonunesp/bls-server/commons/proto"
	"github.com/eduardonunesp/bls-server/server/internal"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50050, "The server port")
)

type augMessageServer struct {
	proto.UnimplementedSendAugMessageServiceServer
	memoryDB *internal.MemoryDB
}

func (a augMessageServer) InitSign(_ context.Context, req *proto.AugMessage) (*proto.InitSignResponse, error) {
	accounts := make([][]byte, len(req.Policy.RequiredAccounts))
	for i, acc := range req.Policy.RequiredAccounts {
		accounts[i] = acc.PublicKey
	}

	am := bls.NewAugMessageWithPolicy(req.Msg, bls.NewPolicy(
		bls.WithMinAccounts(int(req.Policy.MinAccounts)),
		bls.WithRequiredAccounts(accounts...),
	))

	uuid := uuid.New().String()

	a.memoryDB.Set(uuid, am)

	return &proto.InitSignResponse{
		Uuid: uuid,
	}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	proto.RegisterSendAugMessageServiceServer(grpcServer, &augMessageServer{
		memoryDB: internal.NewMemoryDB(),
	})
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
