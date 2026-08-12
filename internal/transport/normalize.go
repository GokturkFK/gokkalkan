// Package transport, GKO-2'nin taşıma katmanı: gerçek bir HTTP isteğini
// proxy.Request'e çevirirken yolu TEK BİR YERDE decode/normalize eder.
//
// Bu paket doğrudan internal/proxy/proxy.go'nun bıraktığı gereksinimi
// karşılar (hasAmbiguousPathMetacharacters yorumu):
//
//	"Gercek decode/normalize sorumlulugu GKO-2'nin transport katmaninda,
//	 tek bir yerde ve buraya girmeden once yapilmali."
//
// Neden önemli: karar katmanı ile hedefe fiilen giden istek aynı yolu
// FARKLI yorumlarsa (parser differential), allowlist kararı bypass
// edilebilir. Örneğin "/repos/%2e%2e/admin" karar katmanında ham string
// olarak "/repos/..." görünüp izin alabilir, ama hedef sunucu onu
// "/admin" olarak çözebilir. Bu yüzden decode BURADA, kararı vermeden
// önce ve yalnızca bir kez yapılır; proxy katmanı decode edilmiş yolu görür.
package transport

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/GokturkFK/gokkalkan/internal/proxy"
)

// HeaderAgentID, agent kimliğinin taşındığı istek başlığıdır.
const HeaderAgentID = "X-Gokkalkan-Agent-Id"

// ErrMissingAgentID, istekte agent kimliği yoksa döner. Kimliksiz istek
// değerlendirilemez ve deny-by-default gereği reddedilir.
var ErrMissingAgentID = errors.New("transport: agent kimligi yok")

// ErrAmbiguousPath, yol tek bir kanonik biçime indirgenemediğinde döner.
// Çift encode edilmiş girdide (örn. "%252e") decode sonrası hâlâ
// metakarakter kalır; hangi katmanın kaç kez decode edeceği belirsiz
// olduğu için istek değerlendirilmeden reddedilir.
var ErrAmbiguousPath = errors.New("transport: yol tek anlamli degil")

// FromRequest, bir HTTP isteğini proxy.Request'e çevirir.
//
// Dönen Request.Path, decode edilmiş ve path.Clean ile normalize edilmiş
// KANONİK yoldur; proxy.Enforcer bunu olduğu gibi değerlendirebilir.
// Hedefe giden istek de aynı kanonik yolla kurulmalıdır (bkz. CanonicalPath),
// yoksa parser differential yeniden doğar.
func FromRequest(r *http.Request) (proxy.Request, error) {
	agentID := r.Header.Get(HeaderAgentID)
	if agentID == "" {
		return proxy.Request{}, ErrMissingAgentID
	}

	p, err := CanonicalPath(r.URL)
	if err != nil {
		return proxy.Request{}, err
	}

	host := r.Host
	if r.URL.Host != "" {
		host = r.URL.Host
	}
	// Port, allowlist eslesmesine girmez (allowlist host bazli); "host:port"
	// geldiginde port ayiklanir.
	if h, _, found := strings.Cut(host, ":"); found {
		host = h
	}

	return proxy.Request{
		AgentID: agentID,
		Method:  r.Method,
		Host:    host,
		Path:    p,
	}, nil
}

// CanonicalPath, URL'in yolunu tek kanonik biçime indirger.
//
// url.URL.Path Go tarafından zaten bir kez percent-decode edilmiştir.
// Burada:
//  1. decode sonrası hâlâ percent-encoded metakarakter kalmışsa (çift
//     encode) istek reddedilir — kaç kez decode edileceği belirsizdir;
//  2. ters bölü reddedilir (bazı sunucular onu ayırıcı sayar);
//  3. path.Clean ile "..", ".", "//" sadeleştirilir.
func CanonicalPath(u *url.URL) (string, error) {
	p := u.Path
	if p == "" {
		p = "/"
	}

	if strings.Contains(p, "\\") {
		return "", ErrAmbiguousPath
	}
	// Go bir kez decode etti; hala "%2e" gibi bir kalinti varsa girdi cift
	// encode edilmis demektir.
	lower := strings.ToLower(p)
	for _, pattern := range []string{"%2e", "%2f", "%5c", "%00"} {
		if strings.Contains(lower, pattern) {
			return "", ErrAmbiguousPath
		}
	}
	if strings.ContainsRune(p, 0) {
		return "", ErrAmbiguousPath
	}

	return path.Clean("/" + strings.TrimPrefix(p, "/")), nil
}
