// Package ipc implementa o transporte IPC do Psychoscope: framing length-prefixed
// sobre streams (Unix domain sockets) carregando mensagens psychoscope.v1.MensagemIPC.
//
// Formato de cada frame:
//
//	[ 4 bytes: uint32 big-endian com N ] [ N bytes: payload protobuf ]
//
// com 1 <= N <= MaxFrameSize. O tamanho declarado é validado antes de qualquer
// alocação para que um peer malicioso não consiga forçar alocações grandes.
package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// HeaderSize é o tamanho do prefixo de tamanho (uint32 big-endian).
	HeaderSize = 4
	// MaxFrameSize é o maior payload aceito por frame (1 MiB).
	MaxFrameSize uint32 = 1 << 20
)

var (
	// ErrEmptyFrame indica um frame com tamanho declarado zero.
	ErrEmptyFrame = errors.New("ipc: frame vazio (tamanho 0)")
	// ErrFrameTooLarge indica um frame acima do limite configurado.
	ErrFrameTooLarge = errors.New("ipc: frame excede o tamanho maximo")
)

// ReadFrame lê um frame completo de r e devolve o payload.
//
// max limita o tamanho aceito (0 significa MaxFrameSize; valores acima de
// MaxFrameSize são reduzidos a MaxFrameSize). Retornos de erro:
//   - io.EOF: stream encerrado limpo, na fronteira de um frame (nenhum byte lido);
//   - io.ErrUnexpectedEOF: stream encerrado no meio do header ou do payload;
//   - ErrEmptyFrame / ErrFrameTooLarge: violação de protocolo; o payload NÃO é lido
//     e a conexão deve ser encerrada pelo chamador.
func ReadFrame(r io.Reader, max uint32) ([]byte, error) {
	if max == 0 || max > MaxFrameSize {
		max = MaxFrameSize
	}

	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err // io.EOF (limpo) ou io.ErrUnexpectedEOF (header parcial)
	}

	n := binary.BigEndian.Uint32(hdr[:])
	switch {
	case n == 0:
		return nil, ErrEmptyFrame
	case n > max:
		return nil, fmt.Errorf("%w: declarado=%d max=%d", ErrFrameTooLarge, n, max)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF // n > 0: EOF aqui é sempre truncamento
		}
		return nil, err
	}
	return payload, nil
}

// WriteFrame escreve header e payload em uma única chamada Write, o que evita
// intercalação parcial quando o writer é um net.Conn. Escritas concorrentes na
// mesma conexão ainda devem ser serializadas pelo chamador (mutex).
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyFrame
	}
	if uint64(len(payload)) > uint64(MaxFrameSize) {
		return fmt.Errorf("%w: tamanho=%d max=%d", ErrFrameTooLarge, len(payload), MaxFrameSize)
	}

	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[:HeaderSize], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)

	_, err := w.Write(buf) // io.Writer garante err != nil em escrita curta
	return err
}

// WriteMessage serializa msg e a envia como um frame.
func WriteMessage(w io.Writer, msg *psychoscopev1.MensagemIPC) error {
	b, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("ipc: marshal: %w", err)
	}
	return WriteFrame(w, b)
}

// ReadMessage lê um frame e o decodifica como MensagemIPC.
// Os erros de ReadFrame são propagados sem alteração (use errors.Is).
func ReadMessage(r io.Reader, max uint32) (*psychoscopev1.MensagemIPC, error) {
	b, err := ReadFrame(r, max)
	if err != nil {
		return nil, err
	}
	msg := &psychoscopev1.MensagemIPC{}
	if err := proto.Unmarshal(b, msg); err != nil {
		return nil, fmt.Errorf("ipc: unmarshal: %w", err)
	}
	return msg, nil
}
