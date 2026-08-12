// Package detect, GK-A2: zehirli tool açıklaması / prompt-injection
// sinyalini tespit eder.
//
// docs/DECISIONS.md Karar 1'e göre bu senaryonun teknik kodu AML.T0110.000
// (AI Agent Tool Poisoning: Definition and Instructions) — tool'un
// model-görünür semantik arayüzü (açıklama, şema, parametre dokümantasyonu,
// annotasyon) zehirlendiğinde. Bu, GK-B'nin honeypot tespitinden (AML.T0053,
// agent yetkisi olmayan bir tool'u çağırdı) farklı bir senaryo: burada
// agent'ın gördüğü bir tool tanımının İÇERİĞİ şüpheli.
//
// PROJECT_PLAN.md'deki disiplin gereği bilinçli olarak ML/anomali yok:
// kurallar deterministik bir desen listesine dayanır, sıfır-FP tezi ancak
// böyle savunulabilir (agresif/olasılıksal tespit meşru açıklamaları da
// engelleyebilir — issue #3'ün risk notu).
package detect

import (
	"regexp"
	"strings"
)

// TechniqueToolPoisoning, correlate.Evaluate'e geçirilecek ATLAS teknik
// kodu (docs/DECISIONS.md Karar 1).
const TechniqueToolPoisoning = "AML.T0110.000"

// ToolDescription, bir agent'ın gördüğü tool tanımının denetlenen
// yüzeyidir: açıklama, parametre dokümantasyonu, agent'a yönelik
// annotasyonlar. Şema (input_schema) bilerek dışarıda — issue #3 sadece
// model-görünür metni kapsıyor.
type ToolDescription struct {
	ToolName    string
	Description string
	ParamDocs   []string
	Annotations []string
}

// Finding, bir ToolDescription'da tespit edilen zehirlenme sinyalidir.
type Finding struct {
	Matched bool
	Pattern string // eşleşen desenin kısa adı, alarm/log için
	Field   string // hangi alanda bulundu: description/param_docs/annotations
}

// patterns, agent'a yönelik gizli talimat/yetki devri denemelerini
// yakalayan deterministik regex listesidir. Her biri NSA MCP güvenlik
// rehberi + OWASP LLM01:2025 (Prompt Injection) taksonomisindeki bilinen
// tool-poisoning kalıplarına karşılık gelir (GK-F1'de tam eşleme
// dokümante edilecek). Case-insensitive.
var patterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"ignore-previous-instructions", regexp.MustCompile(`(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions?`)},
	{"disregard-system-prompt", regexp.MustCompile(`(?i)disregard\s+(the\s+)?(system|earlier)\s+(prompt|instructions?)`)},
	{"hidden-agent-directive", regexp.MustCompile(`(?i)\[\s*(system|assistant)\s*(note|instruction)?\s*:\s*.*(agent|you)\s+must`)},
	{"exfiltrate-credentials", regexp.MustCompile(`(?i)(send|forward|post|exfiltrate)\s+(the\s+)?(api[\s_-]?key|token|credential|secret|password)s?\s+to\b`)},
	{"unauthorized-endpoint-directive", regexp.MustCompile(`(?i)(always|first|before\s+anything)\s+(call|invoke|connect\s+to)\s+https?://`)},
	{"self-referential-elevation", regexp.MustCompile(`(?i)(grant|give|elevate)\s+(yourself|this\s+tool|me)\s+(admin|root|full)\s+access`)},
}

// Scan, ToolDescription'ın tüm denetlenen alanlarını taranan desenlere
// karşı kontrol eder. İlk eşleşmede döner (deterministik, tek sebep
// yeterli — issue #3 AC 1). Eşleşme yoksa Finding.Matched false döner,
// hiçbir alarm/event üretilmez (sıfır-FP, issue #3 AC 2).
func Scan(desc ToolDescription) Finding {
	fields := []struct {
		name  string
		value string
	}{
		{"description", desc.Description},
	}
	for _, d := range desc.ParamDocs {
		fields = append(fields, struct{ name, value string }{"param_docs", d})
	}
	for _, a := range desc.Annotations {
		fields = append(fields, struct{ name, value string }{"annotations", a})
	}

	for _, f := range fields {
		normalized := normalize(f.value)
		for _, p := range patterns {
			if p.re.MatchString(normalized) {
				return Finding{Matched: true, Pattern: p.name, Field: f.name}
			}
		}
	}

	return Finding{}
}

// normalize, format varyasyonlarına karşı dayanıklılık sağlar (issue #3
// AC 3): fazla boşluk/satır sonu tek boşluğa indirgenir, böylece
// "ignore\nprevious   instructions" gibi biçimlendirmeler de yakalanır.
// Kelime sınırları regex'lerdeki \s+ ile zaten esnek tutuluyor; bu adım
// sadece regex motorunun çok satırlı girdide performanslı çalışmasını
// garantiler.
func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
