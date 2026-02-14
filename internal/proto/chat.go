package proto

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type ChatSendHeader struct {
	To        string
	SizeBytes int64
}

type ChatDeliveryHeader struct {
	From      string
	MessageID string
	SizeBytes int64
}

func WriteChatSendHeader(w io.Writer, h ChatSendHeader) error {
	if strings.TrimSpace(h.To) == "" || h.SizeBytes < 0 {
		return fmt.Errorf("invalid chat send header")
	}
	_, err := fmt.Fprintf(w, "CHAT1 SEND %s %d\n", h.To, h.SizeBytes)
	return err
}

func ReadChatSendHeader(r io.Reader) (ChatSendHeader, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return ChatSendHeader{}, br, err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 4 || parts[0] != "CHAT1" || parts[1] != "SEND" {
		return ChatSendHeader{}, br, fmt.Errorf("invalid chat send header")
	}
	n, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || n < 0 {
		return ChatSendHeader{}, br, fmt.Errorf("invalid chat send size")
	}
	return ChatSendHeader{To: parts[2], SizeBytes: n}, br, nil
}

func WriteChatDeliveryHeader(w io.Writer, h ChatDeliveryHeader) error {
	if strings.TrimSpace(h.From) == "" || strings.TrimSpace(h.MessageID) == "" || h.SizeBytes < 0 {
		return fmt.Errorf("invalid chat delivery header")
	}
	_, err := fmt.Fprintf(w, "CHAT1 DELIVER %s %s %d\n", h.From, h.MessageID, h.SizeBytes)
	return err
}

func ReadChatDeliveryHeader(r io.Reader) (ChatDeliveryHeader, *bufio.Reader, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return ChatDeliveryHeader{}, br, err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 5 || parts[0] != "CHAT1" || parts[1] != "DELIVER" {
		return ChatDeliveryHeader{}, br, fmt.Errorf("invalid chat delivery header")
	}
	n, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil || n < 0 {
		return ChatDeliveryHeader{}, br, fmt.Errorf("invalid chat delivery size")
	}
	return ChatDeliveryHeader{From: parts[2], MessageID: parts[3], SizeBytes: n}, br, nil
}

func WriteChatAck(w io.Writer, messageID string) error {
	id := strings.TrimSpace(messageID)
	if id == "" {
		return fmt.Errorf("empty message id")
	}
	_, err := fmt.Fprintf(w, "CHAT1 ACK %s\n", id)
	return err
}

func ReadChatAck(r io.Reader, wantMessageID string) error {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 3 || parts[0] != "CHAT1" || parts[1] != "ACK" {
		return fmt.Errorf("invalid chat ack")
	}
	if parts[2] != strings.TrimSpace(wantMessageID) {
		return fmt.Errorf("chat ack mismatch")
	}
	return nil
}

func WriteKeyLookupRequest(w io.Writer, username string) error {
	u := strings.TrimSpace(username)
	if u == "" {
		return fmt.Errorf("empty username")
	}
	_, err := fmt.Fprintf(w, "LOOKUP %s\n", u)
	return err
}

func ReadKeyLookupRequest(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 2 || parts[0] != "LOOKUP" {
		return "", fmt.Errorf("invalid lookup request")
	}
	return parts[1], nil
}

func WriteKeyLookupResponse(w io.Writer, pubKey string) error {
	if strings.TrimSpace(pubKey) == "" {
		_, err := fmt.Fprint(w, "MISS\n")
		return err
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(pubKey))
	_, err := fmt.Fprintf(w, "FOUND %s\n", b64)
	return err
}

func ReadKeyLookupResponse(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "MISS" {
		return "", fmt.Errorf("not found")
	}
	parts := strings.Fields(line)
	if len(parts) != 2 || parts[0] != "FOUND" {
		return "", fmt.Errorf("invalid lookup response")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
