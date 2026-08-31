package secagg

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

// 本文件实现 gRPC 服务化：
//
// 架构：参与方进程暴露 PartyService gRPC 服务（每阶段一个 Unary RPC），
// 聚合服务器持有 remoteParty（PartyDriver 的 gRPC 客户端代理），由
// Aggregator.Run 按既有同步协议驱动。消息经 JSON codec 传输
// （手写 ServiceDesc，无需 protoc 编译）。
//
// 说明：JSON codec 为自定义编解码，跨语言互操作需对端实现相同 JSON
// 消息契约；生产环境可切换为 protobuf 生成代码（等价 RPC 接口）。

// rpcTimeout 单阶段 RPC 超时。
const rpcTimeout = 30 * time.Second

// partyServiceName gRPC 服务全名。
const partyServiceName = "otpmask.PartyService"

// defaultMaxRecvMsgSize 默认最大接收消息大小（64 MiB）。
// 生产环境应根据维度 n、阈值 t 与明文大小显式调整，防止资源耗尽 DoS。
const defaultMaxRecvMsgSize = 64 << 20 // 64 MiB

// DefaultServerOptions 返回推荐的 gRPC 服务端选项（消息大小限制等）。
func DefaultServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(defaultMaxRecvMsgSize),
		grpc.MaxSendMsgSize(defaultMaxRecvMsgSize),
	}
}

// ---- JSON codec（grpc.ForceServerCodec / ForceCodec）----

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)      { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
func (jsonCodec) Name() string                       { return "json" }

// ---- RPC 消息（复用 secagg 协议消息，JSON 可序列化）----

type (
	advertiseReq  struct{}
	advertiseRsp  struct{ Adv *advertiseMsg }
	shareSeedsReq struct{ Advertises map[int]advertiseMsg }
	shareSeedsRsp struct {
		Bundles     []shareBundleCipher `json:"bundles"`
		Commitments seedCommitments     `json:"commitments"`
	}
	receiveBundlesReq struct{ Bundles []shareBundleCipher }
	emptyRsp          struct{}
	maskedInputReq    struct{ Advertises map[int]advertiseMsg }
	maskedInputRsp    struct{ Y []uint64 }
	unmaskReq         struct{ Online map[int]bool }
	unmaskRsp         struct{ Msg *unmaskMsg }
)

// ---- PartyService 服务端接口 ----

// PartyServiceServer 参与方服务接口（由参与方进程实现）。
type PartyServiceServer interface {
	Advertise(context.Context, *advertiseReq) (*advertiseRsp, error)
	ShareSeeds(context.Context, *shareSeedsReq) (*shareSeedsRsp, error)
	ReceiveBundles(context.Context, *receiveBundlesReq) (*emptyRsp, error)
	MaskedInput(context.Context, *maskedInputReq) (*maskedInputRsp, error)
	Unmask(context.Context, *unmaskReq) (*unmaskRsp, error)
}

// RegisterPartyServiceServer 注册 PartyService 到 gRPC server（JSON codec）。
// 注意：jsonCodec 必须注册到 encoding 表（content-subtype "json"），
// 服务端才能按客户端发送的 content-type 选择该 codec。
func RegisterPartyServiceServer(s *grpc.Server, impl PartyServiceServer) {
	encoding.RegisterCodec(jsonCodec{})
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: partyServiceName,
		HandlerType: (*PartyServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Advertise", Handler: unaryHandler(partyServiceName+"/Advertise", func(ctx context.Context, srv any, in *advertiseReq) (any, error) {
				return srv.(PartyServiceServer).Advertise(ctx, in)
			})},
			{MethodName: "ShareSeeds", Handler: unaryHandler(partyServiceName+"/ShareSeeds", func(ctx context.Context, srv any, in *shareSeedsReq) (any, error) {
				return srv.(PartyServiceServer).ShareSeeds(ctx, in)
			})},
			{MethodName: "ReceiveBundles", Handler: unaryHandler(partyServiceName+"/ReceiveBundles", func(ctx context.Context, srv any, in *receiveBundlesReq) (any, error) {
				return srv.(PartyServiceServer).ReceiveBundles(ctx, in)
			})},
			{MethodName: "MaskedInput", Handler: unaryHandler(partyServiceName+"/MaskedInput", func(ctx context.Context, srv any, in *maskedInputReq) (any, error) {
				return srv.(PartyServiceServer).MaskedInput(ctx, in)
			})},
			{MethodName: "Unmask", Handler: unaryHandler(partyServiceName+"/Unmask", func(ctx context.Context, srv any, in *unmaskReq) (any, error) {
				return srv.(PartyServiceServer).Unmask(ctx, in)
			})},
		},
		Metadata: "otpmask.PartyService",
	}, impl)
}

// unaryHandler 构造标准 Unary RPC handler（泛型指定请求类型，支持拦截器链）。
func unaryHandler[Req any](fullMethod string, fn func(ctx context.Context, srv any, in *Req) (any, error)) grpc.MethodHandler {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := new(Req)
		if err := dec(in); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return fn(ctx, srv, in)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethod}
		handler := func(ctx context.Context, req any) (any, error) { return fn(ctx, srv, req.(*Req)) }
		return interceptor(ctx, in, info, handler)
	}
}

// ---- 参与方服务实现（本地 *party 包装）----

// partyServer 将 *party 暴露为 gRPC 服务。
type partyServer struct {
	p *party
}

// NewPartyServer 构造参与方 gRPC 服务实现。
func NewPartyServer(p *party) PartyServiceServer { return &partyServer{p: p} }

func (s *partyServer) Advertise(ctx context.Context, _ *advertiseReq) (*advertiseRsp, error) {
	adv, err := s.p.advertise(ctx)
	if err != nil {
		return nil, err
	}
	return &advertiseRsp{Adv: &adv}, nil
}

func (s *partyServer) ShareSeeds(ctx context.Context, req *shareSeedsReq) (*shareSeedsRsp, error) {
	bundles, comm, err := s.p.shareSeeds(ctx, req.Advertises)
	if err != nil {
		return nil, err
	}
	return &shareSeedsRsp{Bundles: bundles, Commitments: comm}, nil
}

func (s *partyServer) ReceiveBundles(ctx context.Context, req *receiveBundlesReq) (*emptyRsp, error) {
	if err := s.p.receiveBundles(ctx, req.Bundles); err != nil {
		return nil, err
	}
	return &emptyRsp{}, nil
}

func (s *partyServer) MaskedInput(ctx context.Context, req *maskedInputReq) (*maskedInputRsp, error) {
	y, err := s.p.maskedInput(ctx, req.Advertises)
	if err != nil {
		return nil, err
	}
	return &maskedInputRsp{Y: y}, nil
}

func (s *partyServer) Unmask(ctx context.Context, req *unmaskReq) (*unmaskRsp, error) {
	msg, err := s.p.unmask(ctx, req.Online)
	if err != nil {
		return nil, err
	}
	return &unmaskRsp{Msg: &msg}, nil
}

// ---- 服务器侧远程参与方（PartyDriver 的 gRPC 客户端代理）----

// remoteParty 通过 gRPC 连接参与方服务的 PartyDriver 实现。
type remoteParty struct {
	id     int
	conn   *grpc.ClientConn
	dropAt Round // 测试注入掉线（默认永不）
}

// NewRemoteParty 构造连接指定参与方服务的远程驱动。
func NewRemoteParty(conn *grpc.ClientConn, id int) PartyDriver {
	return &remoteParty{id: id, conn: conn, dropAt: 999}
}

func (r *remoteParty) partyID() int { return r.id }
func (r *remoteParty) dropped(round Round) bool {
	return int(round) >= int(r.dropAt)
}

func (r *remoteParty) advertise(ctx context.Context) (advertiseMsg, error) {
	var in advertiseReq
	var out advertiseRsp
	if err := r.call(ctx, "Advertise", &in, &out); err != nil {
		return advertiseMsg{}, err
	}
	if out.Adv == nil {
		return advertiseMsg{}, errNilRPCResponse("Advertise")
	}
	return *out.Adv, nil
}

func (r *remoteParty) shareSeeds(ctx context.Context, advertises map[int]advertiseMsg) ([]shareBundleCipher, seedCommitments, error) {
	var out shareSeedsRsp
	if err := r.call(ctx, "ShareSeeds", &shareSeedsReq{Advertises: advertises}, &out); err != nil {
		return nil, seedCommitments{}, err
	}
	return out.Bundles, out.Commitments, nil
}

func (r *remoteParty) receiveBundles(ctx context.Context, bundles []shareBundleCipher) error {
	var out emptyRsp
	return r.call(ctx, "ReceiveBundles", &receiveBundlesReq{Bundles: bundles}, &out)
}

func (r *remoteParty) maskedInput(ctx context.Context, advertises map[int]advertiseMsg) ([]uint64, error) {
	var out maskedInputRsp
	if err := r.call(ctx, "MaskedInput", &maskedInputReq{Advertises: advertises}, &out); err != nil {
		return nil, err
	}
	return out.Y, nil
}

func (r *remoteParty) unmask(ctx context.Context, online map[int]bool) (unmaskMsg, error) {
	var out unmaskRsp
	if err := r.call(ctx, "Unmask", &unmaskReq{Online: online}, &out); err != nil {
		return unmaskMsg{}, err
	}
	if out.Msg == nil {
		return unmaskMsg{}, errNilRPCResponse("Unmask")
	}
	return *out.Msg, nil
}

// call 发起 Unary gRPC 调用（JSON codec）。
// method 须以 "/" 前缀（gRPC 完整方法名规范：/service/Method）。
func (r *remoteParty) call(ctx context.Context, method string, in, out any) error {
	return r.conn.Invoke(ctx, "/"+partyServiceName+"/"+method, in, out, grpc.ForceCodec(jsonCodec{}))
}

type errNilRPCResponse string

func (e errNilRPCResponse) Error() string { return "secagg: " + string(e) + " 返回空响应" }
