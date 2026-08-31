package secagg

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1 << 20

// startPartyServer 在内存 bufconn 上启动参与方 gRPC 服务，返回客户端连接。
func startPartyServer(t *testing.T, p *party) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	RegisterPartyServiceServer(s, NewPartyServer(p))
	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// G-10 远程参与方（gRPC 全链路）端到端聚合。
func TestRemotePartiesOverGRPC(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)

	drivers := make([]PartyDriver, 4)
	for i, p := range parties {
		conn := startPartyServer(t, p)
		drivers[i] = NewRemoteParty(conn, i)
	}

	agg, _ := NewAggregator(cfg)
	res, err := agg.Run(drivers)
	if err != nil {
		t.Fatal(err)
	}
	want := sumVectors(values, cfg.Modulus)
	for i := range want {
		if res.Sum[i] != want[i] {
			t.Fatalf("远程聚合分量 %d 错误: got=%d want=%d", i, res.Sum[i], want[i])
		}
	}
}

// G-10b 远程参与方多配置回归 + 远程掉线（Round2 前）。
func TestRemotePartiesConfigsAndDropout(t *testing.T) {
	cfg := testConfig(5, 3, 8)
	values := make([][]uint64, 5)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)

	drivers := make([]PartyDriver, 5)
	for i, p := range parties {
		conn := startPartyServer(t, p)
		rp := NewRemoteParty(conn, i).(*remoteParty)
		if i == 4 {
			rp.dropAt = Round2MaskedInput // 远程参与方 4 掉线
		}
		drivers[i] = rp
	}

	agg, _ := NewAggregator(cfg)
	res, err := agg.Run(drivers)
	if err != nil {
		t.Fatal(err)
	}
	want := sumVectors(values[:4], cfg.Modulus)
	for i := range want {
		if res.Sum[i] != want[i] {
			t.Fatalf("远程掉线场景分量 %d 错误: got=%d want=%d", i, res.Sum[i], want[i])
		}
	}
}
