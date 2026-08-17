// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): ChannelTest; TECH(8): go test,httptest]
// @purpose Verify the in-app channel test button: it must create a bell notification and return
//
//	ok:true instead of the old "unknown channel type: in-app" delivery error.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, channel, in-app, bell, testChannel, notification
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

func TestTestChannel_InApp(t *testing.T) {
	srv, buf := newServer(t)
	ctx := context.Background()

	chID, err := srv.store.CreateChannel(ctx, store.Channel{Type: "in-app", Name: "bell", Enabled: true})
	if err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/channels/"+itoa64(chID)+"/test", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("want ok:true, got %s", rec.Body.String())
	}
	// The bell got the test row.
	var n int
	_ = srv.store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notifications WHERE kind='test' AND title LIKE '%channel test%'`).Scan(&n)
	if n != 1 {
		t.Fatalf("want 1 test notification, got %d", n)
	}
	printIMPFromBuf(t, buf)
}
