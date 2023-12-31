// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.24.3
// source: service.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// SendAugMessageServiceClient is the client API for SendAugMessageService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SendAugMessageServiceClient interface {
	InitSign(ctx context.Context, in *AugMessage, opts ...grpc.CallOption) (*InitSignResponse, error)
}

type sendAugMessageServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSendAugMessageServiceClient(cc grpc.ClientConnInterface) SendAugMessageServiceClient {
	return &sendAugMessageServiceClient{cc}
}

func (c *sendAugMessageServiceClient) InitSign(ctx context.Context, in *AugMessage, opts ...grpc.CallOption) (*InitSignResponse, error) {
	out := new(InitSignResponse)
	err := c.cc.Invoke(ctx, "/proto.SendAugMessageService/InitSign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SendAugMessageServiceServer is the server API for SendAugMessageService service.
// All implementations must embed UnimplementedSendAugMessageServiceServer
// for forward compatibility
type SendAugMessageServiceServer interface {
	InitSign(context.Context, *AugMessage) (*InitSignResponse, error)
	mustEmbedUnimplementedSendAugMessageServiceServer()
}

// UnimplementedSendAugMessageServiceServer must be embedded to have forward compatible implementations.
type UnimplementedSendAugMessageServiceServer struct {
}

func (UnimplementedSendAugMessageServiceServer) InitSign(context.Context, *AugMessage) (*InitSignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InitSign not implemented")
}
func (UnimplementedSendAugMessageServiceServer) mustEmbedUnimplementedSendAugMessageServiceServer() {}

// UnsafeSendAugMessageServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SendAugMessageServiceServer will
// result in compilation errors.
type UnsafeSendAugMessageServiceServer interface {
	mustEmbedUnimplementedSendAugMessageServiceServer()
}

func RegisterSendAugMessageServiceServer(s grpc.ServiceRegistrar, srv SendAugMessageServiceServer) {
	s.RegisterService(&SendAugMessageService_ServiceDesc, srv)
}

func _SendAugMessageService_InitSign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AugMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SendAugMessageServiceServer).InitSign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.SendAugMessageService/InitSign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SendAugMessageServiceServer).InitSign(ctx, req.(*AugMessage))
	}
	return interceptor(ctx, in, info, handler)
}

// SendAugMessageService_ServiceDesc is the grpc.ServiceDesc for SendAugMessageService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SendAugMessageService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.SendAugMessageService",
	HandlerType: (*SendAugMessageServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "InitSign",
			Handler:    _SendAugMessageService_InitSign_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "service.proto",
}
