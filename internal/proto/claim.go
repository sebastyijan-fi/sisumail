package proto

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Claim v1 is a minimal line protocol over an SSH channel.
//
// Request:
//   CLAIM1 <username> <base64(pubkey_authorized_line)> <invite_code>\n
//
// Response (success):
//   CLAIM1 OK <canonical_username> <ipv6> <address> <invite_n>\n
//   INVITE <code>\n   (repeated invite_n times)
//   END\n
//
// Response (error):
//   CLAIM1 ERR <message>\n

type ClaimRequest struct {
	Username   string
	PubKeyText string
	InviteCode string
}

type ClaimResponse struct {
	OK       bool
	Message  string
	Username string
	IPv6     string
	Address  string
	Invites  []string
}

func WriteClaimRequest(w io.Writer, req ClaimRequest) error {
	u := strings.TrimSpace(req.Username)
	pk := strings.TrimSpace(req.PubKeyText)
	code := strings.TrimSpace(req.InviteCode)
	if u == "" || pk == "" || code == "" {
		return fmt.Errorf("invalid claim request")
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(pk))
	_, err := fmt.Fprintf(w, "CLAIM1 %s %s %s\n", u, b64, code)
	return err
}

func ReadClaimRequest(r io.Reader) (ClaimRequest, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return ClaimRequest{}, err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 4 || parts[0] != "CLAIM1" {
		return ClaimRequest{}, fmt.Errorf("invalid claim request")
	}
	rawPub, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return ClaimRequest{}, fmt.Errorf("invalid pubkey encoding")
	}
	req := ClaimRequest{
		Username:   parts[1],
		PubKeyText: string(rawPub),
		InviteCode: parts[3],
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.PubKeyText) == "" || strings.TrimSpace(req.InviteCode) == "" {
		return ClaimRequest{}, fmt.Errorf("invalid claim request")
	}
	return req, nil
}

func WriteClaimResponse(w io.Writer, resp ClaimResponse) error {
	if !resp.OK {
		msg := strings.TrimSpace(resp.Message)
		if msg == "" {
			msg = "error"
		}
		msg = strings.ReplaceAll(msg, "\n", " ")
		_, err := fmt.Fprintf(w, "CLAIM1 ERR %s\n", msg)
		return err
	}
	n := len(resp.Invites)
	_, err := fmt.Fprintf(w, "CLAIM1 OK %s %s %s %d\n", strings.TrimSpace(resp.Username), strings.TrimSpace(resp.IPv6), strings.TrimSpace(resp.Address), n)
	if err != nil {
		return err
	}
	for _, c := range resp.Invites {
		cc := strings.TrimSpace(c)
		if cc == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "INVITE %s\n", cc); err != nil {
			return err
		}
	}
	_, err = fmt.Fprint(w, "END\n")
	return err
}

func ReadClaimResponse(r io.Reader) (ClaimResponse, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return ClaimResponse{}, err
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "CLAIM1 ERR ") {
		return ClaimResponse{OK: false, Message: strings.TrimSpace(strings.TrimPrefix(line, "CLAIM1 ERR "))}, nil
	}
	parts := strings.Fields(line)
	if len(parts) != 6 || parts[0] != "CLAIM1" || parts[1] != "OK" {
		return ClaimResponse{}, fmt.Errorf("invalid claim response")
	}
	invN, err := strconv.Atoi(parts[5])
	if err != nil || invN < 0 || invN > 64 {
		return ClaimResponse{}, fmt.Errorf("invalid invite count")
	}
	resp := ClaimResponse{
		OK:       true,
		Username: parts[2],
		IPv6:     parts[3],
		Address:  parts[4],
	}
	for i := 0; i < invN; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			return ClaimResponse{}, err
		}
		l = strings.TrimSpace(l)
		p := strings.Fields(l)
		if len(p) != 2 || p[0] != "INVITE" {
			return ClaimResponse{}, fmt.Errorf("invalid invite line")
		}
		resp.Invites = append(resp.Invites, p[1])
	}
	end, err := br.ReadString('\n')
	if err != nil {
		return ClaimResponse{}, err
	}
	if strings.TrimSpace(end) != "END" {
		return ClaimResponse{}, fmt.Errorf("invalid claim response terminator")
	}
	return resp, nil
}
