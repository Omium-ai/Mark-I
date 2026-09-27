//go:build integration

// The closed-set half of FR-SPINE-016 (02 §88): per-event receipts are issued
// for exactly six classes "and for nothing else by default". A chain that will
// mint a receipt for whatever class a caller names is a log, not a bounded
// audit surface — so the rejection is the requirement, not a guard clause.
//
// It is implemented TWICE: the Go allow-list in server_record.go:62-64 and
// m1_002's CHECK constraints. Two implementations of one rule is good defence
// and a classic drift hazard — either could be widened while the other still
// looks like it is guarding, and nothing proved they agree. These tests pin
// them to each other and to 02 §88's literal list.
//
// Gates: inherits integration_test.go's setup(t) (M1_MIGRATE_PG_DSN, hard
// failure under M1_REQUIRE_STORES=1). The scratch database carries the REAL
// migration tree, so the constraints read here are the ones prod executes.

package receipts_test

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// perEventClasses is 02 §88's list plus ADR-0004's key_rotation (m1_066: the
// retiring chain key's hand-over receipt), C13's verifier_promotion and the
// founder ruling's quarantine_deletion (m1_080), spelled out rather than
// derived from the maps under test: a test that computed them from the same
// maps it grades would agree with any edit to them, including the edit that
// drops a class.
var perEventClasses = []string{
	"noise_certificate", "memory_admission", "bundle_publication",
	"corpus_export", "coverage_transition", "guard_contamination",
	"key_rotation", "verifier_promotion", "quarantine_deletion", "evidence_deletion",
}

// unknownClass is 02 §9's "seventh event type": a name no layer knows. Shaped
// like a real M1P event so a widened allow-list would plausibly contain it.
const unknownClass = "prompt_capture"

// errProbeRollback unwinds a raw-SQL probe. The probes exist to learn what the
// constraints do, and m1_receipts is append-only — a probe that committed
// could never be taken back out.
var errProbeRollback = errors.New("probe complete; roll back")

// classLiteral matches the quoted class names inside a constraint definition.
// Both constraints read here contain no other string literals, so this reads
// the set the database actually enforces rather than the migration's text.
var classLiteral = regexp.MustCompile(`'([a-z_]+)'::text`)

func classesInConstraint(t *testing.T, h *harness, conname string) map[string]bool {
	t.Helper()
	var def string
	if err := h.admin.QueryRow(context.Background(),
		`SELECT pg_get_constraintdef(oid) FROM pg_constraint
		  WHERE conrelid = 'm1_receipts'::regclass AND conname = $1`, conname).Scan(&def); err != nil {
		t.Fatalf("constraint %s is not on m1_receipts (%v) — either m1_002 dropped the closed set or renamed it; both need a decision, not a green test", conname, err)
	}
	out := map[string]bool{}
	for _, m := range classLiteral.FindAllStringSubmatch(def, -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatalf("%s admits no named class: %s", conname, def)
	}
	return out
}

func classSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

func sortedClasses(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// assertSameClasses grades mutual inclusion AND size. Size is not implied by
// the two loops when a set is empty, and an empty set is exactly what makes
// "every class was admitted" true for free.
func assertSameClasses(t *testing.T, what string, want, got map[string]bool) {
	t.Helper()
	var missing, extra []string
	for c := range want {
		if !got[c] {
			missing = append(missing, c)
		}
	}
	for c := range got {
		if !want[c] {
			extra = append(extra, c)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 || len(want) != len(got) {
		t.Errorf("%s holds %d classes %v, want the %d of %v (missing %v, unexpected %v)",
			what, len(got), sortedClasses(got), len(want), sortedClasses(want), missing, extra)
	}
}

// TestIntegrationRecordClassesAgreeWithM1_002 grades the two implementations
// against each other and against 02 §88, by set and by size. A Go set that
// grew a seventh class the CHECK has never heard of, or a migration that
// widened the CHECK past what Go will write, fails here by name.
func TestIntegrationRecordClassesAgreeWithM1_002(t *testing.T) {
	h := setup(t)

	// Anti-vacuity: every loop in this file iterates one of these two maps.
	if got := len(receipts.ServerRecordTypes); got != 8 {
		t.Fatalf("ServerRecordTypes holds %d classes %v, want the 8 server-originated arms of ck_m1_receipts_record_shape (m1_002 + m1_068 + m1_069 + m1_080 + m1_099)",
			got, sortedClasses(receipts.ServerRecordTypes))
	}
	if got := len(receipts.DeviceOriginTypes); got != 3 {
		t.Fatalf("DeviceOriginTypes holds %d classes %v, want the 3 of ck_m1_receipts_origin",
			got, sortedClasses(receipts.DeviceOriginTypes))
	}

	// 02 §88's six = both Go sets minus `checkpoint`, which seals a BATCH and
	// is therefore not a per-event class (chain.go's Checkpoint: "per-event
	// receipts exist only for the six named classes; everything else rides
	// under a checkpoint").
	perEvent := map[string]bool{}
	for c := range receipts.ServerRecordTypes {
		perEvent[c] = true
	}
	for c := range receipts.DeviceOriginTypes {
		perEvent[c] = true
	}
	delete(perEvent, "checkpoint")
	assertSameClasses(t, "the Go sets' per-event classes", classSet(perEventClasses), perEvent)

	// The database's closed set is those six plus `checkpoint` (a batch seal)
	// and `discontinuity` (a LINK, never a repair — m1_002 header). No Go set
	// names discontinuity, because controld has no writer for it; this
	// equality is what fails if a ninth class appears in either place without
	// a decision about which set owns it.
	assertSameClasses(t, "m1_receipts.record_type",
		classSet(append(append([]string{}, perEventClasses...), "checkpoint", "discontinuity")),
		classesInConstraint(t, h, "m1_receipts_record_type_check"))

	// The device-origin membership set, same treatment: chain.go's comment
	// claims it "mirrors ck_m1_receipts_origin's equivalence", and a mirror
	// nobody compares is a copy.
	assertSameClasses(t, "ck_m1_receipts_origin",
		receipts.DeviceOriginTypes,
		classesInConstraint(t, h, "ck_m1_receipts_origin"))
}

// TestIntegrationServerRecordClassIsClosedInGoAndInPostgres drives the same
// rule behaviourally: every allow-list member is admitted end to end, every
// class outside it is refused by name, and Postgres refuses the unknown class
// on its own — proven with the Go guard out of the picture, since a test that
// only ever reaches the database through AppendServerRecordTx is grading the
// `if` statement and calling it a constraint.
func TestIntegrationServerRecordClassIsClosedInGoAndInPostgres(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	append1 := func(class string) error {
		return h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			_, err := h.store.AppendServerRecordTx(ctx, tx, h.tenantA, receipts.ServerRecord{
				RecordType: class,
				SubjectID:  v7(t),
				IssuedAt:   at,
				Fields:     map[string]any{"probe": class},
			})
			return err
		})
	}

	// Positive control, one per allow-list member: a class the `if` admits is
	// a class the CHECK admits too. A member m1_002 has never heard of fails
	// here — the "Go set grew a class the database does not know" direction.
	allowed := sortedClasses(receipts.ServerRecordTypes)
	for _, class := range allowed {
		if err := append1(class); err != nil {
			t.Fatalf("%s is in ServerRecordTypes but the chain would not take it: %v", class, err)
		}
	}
	var landed []string
	rows, err := h.admin.Query(ctx, `SELECT record_type FROM m1_receipts ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var rt string
		if err := rows.Scan(&rt); err != nil {
			t.Fatal(err)
		}
		landed = append(landed, rt)
	}
	rows.Close()
	sort.Strings(landed)
	if strings.Join(landed, ",") != strings.Join(allowed, ",") {
		t.Fatalf("the chain holds %v, want one receipt per allow-list member %v", landed, allowed)
	}

	// Refusal, Go side. The device-origin classes are excluded so a caller
	// cannot mint device-attested history by picking a string, discontinuity
	// because it carries no subject, and unknownClass because 02 §88's set is
	// closed. The error must NAME the class: "invalid record type" leaves an
	// operator to guess which of a batch's records was refused.
	refused := append(sortedClasses(receipts.DeviceOriginTypes), "discontinuity", unknownClass)
	for _, class := range refused {
		err := append1(class)
		if err == nil {
			t.Errorf("%s is outside ServerRecordTypes but AppendServerRecordTx wrote it", class)
			continue
		}
		if !strings.Contains(err.Error(), class) {
			t.Errorf("refusing %s: error does not name the class: %v", class, err)
		}
	}
	seq, head, _, err := h.store.Head(ctx, h.tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if seq != int64(len(allowed)) {
		t.Fatalf("chain head at %d after %d refusals, want %d — a refused class still moved the chain",
			seq, len(refused), len(allowed))
	}

	// Postgres' half of the same rule, driven as raw SQL on the request-path
	// connection shape (app role, tenant GUC set): the Go guard cannot be what
	// refuses these. Rolled back either way — m1_receipts is append-only, so a
	// probe that committed could not be taken back out.
	subject := v7(t)
	probe := func(class string) error {
		return h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `
				INSERT INTO m1_receipts
				  (tenant_id, seq, prev_receipt_hash, receipt_hash, payload, record_type,
				   server_key_id, server_signature, subject_id)
				VALUES ($1, $2, $3, $4, '{"probe":true}', $5, $6, $7, $8)`,
				h.tenantA.UUID(), seq+1, head[:], bytes.Repeat([]byte{0x5a}, 32), class,
				h.chainKey.KeyID(), bytes.Repeat([]byte{0x5b}, 64), subject); err != nil {
				return err
			}
			return errProbeRollback
		})
	}

	// The control that makes the refusal below attributable: this row differs
	// from it in the record_type column and NOTHING else, so if the unknown
	// class is refused, the class is why — not a length check, an FK, or RLS.
	if err := probe("corpus_export"); !errors.Is(err, errProbeRollback) {
		t.Fatalf("the raw-SQL control row was rejected, so the refusal below would prove nothing about record_type: %v", err)
	}
	var pgErr *pgconn.PgError
	err = probe(unknownClass)
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("raw insert of %q: want a check violation from m1_002, got %v", unknownClass, err)
	}
	// Both m1_002 arms enumerate the closed set (record_type's own list and
	// ck_m1_receipts_record_shape, which has no arm for an unknown class);
	// Postgres does not promise which fires first, so either answer is the
	// database refusing — a third name would mean it refused for some other
	// reason and the closed set went untested.
	if pgErr.ConstraintName != "m1_receipts_record_type_check" && pgErr.ConstraintName != "ck_m1_receipts_record_shape" {
		t.Fatalf("raw insert of %q was refused by %s, not by m1_002's closed set", unknownClass, pgErr.ConstraintName)
	}
}
