package rules

import (
	"fmt"
	"testing"

	"github.com/psychoscope-io/psychoscope-core/internal/detection/ruletest"
)

// Pior caso: um tipo vigiado muito frequente, espalhado por muitos grupos que ficam abaixo do limiar.
// Cada evento obriga a regra a examinar a janela inteira do tipo.
func BenchmarkGenericBurstManyGroups(b *testing.B) {
	for _, n := range []int{2_000, 20_000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := Default()
			cfg.GenericBurst.Types = []string{"login.falha"}
			cfg.GenericBurst.GroupBy = []string{"usuario"}
			in := make([]ruletest.Input, n)
			for i := range in {
				in[i] = ruletest.Gen(float64(i)*55/float64(n), "login.falha", map[string]string{"usuario": fmt.Sprint("u", i%5000)})
			}
			rs, _ := Build(cfg)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ruletest.Run(b, rs, in...)
			}
		})
	}
}
