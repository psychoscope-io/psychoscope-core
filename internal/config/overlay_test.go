package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type inner struct {
	Window  time.Duration `json:"window"`
	Count   int           `json:"count"`
	Ratio   float64       `json:"ratio"`
	Names   []string      `json:"names"`
	Ports   []int         `json:"ports"`
	Flag    bool          `json:"flag"`
	private int
	NoTag   int
	Skipped int `json:"-"`
}

func TestOverlayStructPartialAndTyped(t *testing.T) {
	v := inner{Window: time.Second, Count: 5, Names: []string{"a"}}
	err := overlayStruct(json.RawMessage(`{"window":"2m30s","ratio":0.25,"names":["x","y"],"ports":[22,3389],"flag":true}`), &v, "t")
	if err != nil {
		t.Fatal(err)
	}
	if v.Window != 150*time.Second || v.Count != 5 || v.Ratio != 0.25 || len(v.Names) != 2 || v.Ports[1] != 3389 || !v.Flag {
		t.Fatalf("overlay: %+v", v)
	}
	_ = v.private
}

func TestOverlayStructErrors(t *testing.T) {
	cases := map[string]string{
		"campo desconhecido":    `{"bogus":1}`,
		"campo sem tag":         `{"NoTag":1}`,
		"campo ignorado":        `{"Skipped":1}`,
		"duracao como numero":   `{"window":10}`,
		"duracao invalida":      `{"window":"dez segundos"}`,
		"tipo errado":           `{"count":"muitos"}`,
		"fracao em inteiro":     `{"count":1.5}`,
		"nao e objeto":          `[1,2]`,
		"lista com tipo errado": `{"ports":["a"]}`,
	}
	for name, body := range cases {
		var v inner
		if err := overlayStruct(json.RawMessage(body), &v, "t"); err == nil {
			t.Errorf("%s: esperado erro", name)
		}
	}
	var v inner
	err := overlayStruct(json.RawMessage(`{"bogus":1}`), &v, "detection.scan")
	if err == nil || !strings.Contains(err.Error(), "detection.scan") || !strings.Contains(err.Error(), "validos: count, flag, names, ports, ratio, window") {
		t.Fatalf("a mensagem deve citar o caminho e os campos validos: %v", err)
	}
	if err := overlayStruct(json.RawMessage(`{}`), inner{}, "t"); err == nil {
		t.Error("destino nao-ponteiro deve falhar")
	}
}
