package ctl

import (
	"fmt"
	"io"

	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/proto"
)

func marshal(r *psychoscopev1.RespostaControle) ([]byte, error) { return proto.Marshal(r) }

func unmarshalRequest(b []byte) (*psychoscopev1.RequisicaoControle, error) {
	req := &psychoscopev1.RequisicaoControle{}
	if err := proto.Unmarshal(b, req); err != nil {
		return nil, fmt.Errorf("%w: %w", errBadRequest, err)
	}
	return req, nil
}

// WriteRequest envia uma requisicao (usado pela CLI e pelos testes).
func WriteRequest(w io.Writer, r *psychoscopev1.RequisicaoControle) error {
	b, err := proto.Marshal(r)
	if err != nil {
		return err
	}
	return ipc.WriteFrame(w, b)
}

// ReadResponse le uma resposta (usado pela CLI e pelos testes).
func ReadResponse(r io.Reader) (*psychoscopev1.RespostaControle, error) {
	b, err := ipc.ReadFrame(r, 0)
	if err != nil {
		return nil, err
	}
	resp := &psychoscopev1.RespostaControle{}
	if err := proto.Unmarshal(b, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
