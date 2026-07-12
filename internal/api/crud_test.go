// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): HTTP; TECH(8): go test,httptest]
// @purpose Verify REST CRUD over the mux: create/get/list/update/delete + status mapping
//
//	(201/200/400/404/409). Prints [IMP:7-10] lines (Semantic Trace).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, http, CRUD, REST, vms, checks, domains, httptest, status
// STRUCTURE: ▶ ┌server┐ → ○ do(method,path,body) → 〈status+decode〉 → ⎋ assert
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func do(srv *Server, method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dst); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
}

func assertContains(t *testing.T, buf interface{ String() string }, anchor string) {
	t.Helper()
	if !strings.Contains(buf.String(), anchor) {
		t.Errorf("Anti-Illusion: missing Semantic Trace anchor %q", anchor)
	}
}

func TestHTTP_VMCRUD(t *testing.T) {
	srv, buf := newServer(t)

	// Create.
	rec := do(srv, http.MethodPost, "/api/vms",
		`{"name":"web1","hostname":"10.0.0.1","port_ssh":22,"tags":["a","b"],"cost_monthly":5.5,"currency":"USD"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &created)
	idStr := strconv.FormatInt(created.ID, 10)

	// Get.
	rec = do(srv, http.MethodGet, "/api/vms/"+idStr, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get want 200, got %d", rec.Code)
	}
	var vm map[string]any
	decode(t, rec, &vm)
	if vm["name"] != "web1" {
		t.Fatalf("get name mismatch: %v", vm["name"])
	}

	// List.
	rec = do(srv, http.MethodGet, "/api/vms", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d", rec.Code)
	}
	var list []map[string]any
	decode(t, rec, &list)
	if len(list) != 1 {
		t.Fatalf("list want 1, got %d", len(list))
	}

	// Update.
	rec = do(srv, http.MethodPut, "/api/vms/"+idStr, `{"name":"web1","hostname":"10.0.0.2","port_ssh":2222}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Validation -> 400.
	rec = do(srv, http.MethodPost, "/api/vms", `{"name":"","hostname":"h","port_ssh":22}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validation want 400, got %d", rec.Code)
	}

	// Unknown id -> 404.
	rec = do(srv, http.MethodGet, "/api/vms/9999", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown want 404, got %d", rec.Code)
	}

	// Delete.
	rec = do(srv, http.MethodDelete, "/api/vms/"+idStr, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete want 200, got %d", rec.Code)
	}

	printIMPFromBuf(t, buf)
	assertContains(t, buf, "[IMP:8][CreateVM][CREATED]")
}

func TestHTTP_CheckCRUD(t *testing.T) {
	srv, buf := newServer(t)
	// Need a VM first.
	rec := do(srv, http.MethodPost, "/api/vms", `{"name":"v","hostname":"h","port_ssh":22}`)
	var vm struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &vm)

	rec = do(srv, http.MethodPost, "/api/checks",
		`{"vm_id":`+strconv.FormatInt(vm.ID, 10)+`,"target_type":"vm","check_type":"ping","interval_sec":30,"params":{"count":3}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create check want 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// target_type=vm without vm_id -> 400.
	rec = do(srv, http.MethodPost, "/api/checks", `{"target_type":"vm","check_type":"ping","interval_sec":30}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validation want 400, got %d", rec.Code)
	}

	// List.
	rec = do(srv, http.MethodGet, "/api/checks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list checks want 200, got %d", rec.Code)
	}

	printIMPFromBuf(t, buf)
	assertContains(t, buf, "[IMP:8][CreateCheck][CREATED]")
}

func TestHTTP_DomainCRUD_Duplicate(t *testing.T) {
	srv, buf := newServer(t)
	rec := do(srv, http.MethodPost, "/api/domains", `{"name":"example.com","monitor_tls":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create domain want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	// Duplicate -> 409.
	rec = do(srv, http.MethodPost, "/api/domains", `{"name":"example.com"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate want 409, got %d", rec.Code)
	}
	// List.
	rec = do(srv, http.MethodGet, "/api/domains", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list domains want 200, got %d", rec.Code)
	}

	printIMPFromBuf(t, buf)
	assertContains(t, buf, "[IMP:8][CreateDomain][CREATED]")
}
