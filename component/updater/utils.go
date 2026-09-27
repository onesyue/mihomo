package updater

import (
	"context"
	"io"
	"time"

	mihomoHttp "github.com/metacubex/mihomo/component/http"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

const defaultHttpTimeout = time.Second * 90

func downloadForBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHttpTimeout)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// saveFile writes a downloaded geodata file, confined to the safe path that
// contains it (YueLink; see C.Path.OpenFileBeneath).
func saveFile(bytes []byte, path string) error {
	return C.Path.WriteFileBeneath(path, bytes, 0o644)
}
