package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rsc/rsc/qr"
)

// Source represent a totp source
type Source struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Period int    `json:"period"`
	Digits int    `json:"digits"`
}

// Valid returns an error if Source is invalid, otherwize it returns nil
func (s *Source) Valid() error {
	if s.Name == "" {
		return errors.New("Name is required")
	}
	if s.Secret == "" {
		return errors.New("Secret is required")
	}
	if s.Period == 0 {
		return errors.New("Period must be greater than 0")
	}
	if s.Digits == 0 {
		return errors.New("Digits must be greater than 0")
	}

	return nil
}

// Code generates a two factor authentication code
//
// Originally written by Joshua Peek <josh@joshpeek.com>
// https://github.com/josh/totp/blob/9b587d6bc564eadeae4787a4dd571fd810fc0a8c/totp.go#L58
//
// Copyright (c) 2014 Joshua Peek
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
func (s *Source) Code() string {
	key, _ := base32.StdEncoding.DecodeString(strings.ToUpper(s.Secret))
	hash := hmac.New(sha1.New, key)
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, time.Now().Unix()/int64(s.Period))
	hash.Write(b.Bytes())

	h := hash.Sum(nil)
	o := h[len(h)-1] & 0xf
	c := int32(h[o]&0x7f)<<24 | int32(h[o+1])<<16 | int32(h[o+2])<<8 | int32(h[o+3])
	return fmt.Sprintf("%010d", c%100000000)[4:10]
}

// Qrcode returns the QR code of the TotpSource in PNG format.
func (s *Source) Qrcode() (*qr.Code, error) {
	params := url.Values{
		"secret": []string{s.Secret},
		"digits": {strconv.Itoa(s.Digits)},
		"period": {strconv.Itoa(s.Period)},
	}

	u := &url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     fmt.Sprintf("/%s", s.Name),
		RawQuery: params.Encode(),
	}

	c, err := qr.Encode(u.String(), qr.M)
	if err != nil {
		return nil, err
	}

	return c, nil
}
