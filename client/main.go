package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/eduardonunesp/bls-server/commons/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	port = flag.Int("port", 50050, "The server port")
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial(
		fmt.Sprintf("localhost:%d", *port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := proto.NewSendAugMessageServiceClient(conn)
	result, err := client.InitSign(context.Background(), &proto.AugMessage{
		Msg: []byte("Hello World"),
		Signatures: [][]byte{
			[]byte("0x01"),
			[]byte("0x02"),
		},
		Policy: &proto.Policy{
			MinAccounts: 2,
			RequiredAccounts: []*proto.Account{
				{
					PublicKey: []byte("0x01"),
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("UUID: %+v\n", result)
}
