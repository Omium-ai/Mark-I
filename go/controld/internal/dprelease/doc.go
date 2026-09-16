// Package dprelease owns the differential-privacy release path: the (k,m)
// gate's candidate query, contribution bounding and the integer Laplace
// mechanism (mechanisms.go), the single-transaction publication whose
// deferred trigger debits the ε ledger for every counted tenant (release.go,
// migrations/m1_064), and the tenant-visible budget read (05 §5). It is the
// ONLY path by which anything derived from more than one tenant's data
// becomes visible to anyone. Its pool opens against the BYPASSRLS
// `mark1_federation_worker` role (m1_060 §5); the budget read rides the
// NOBYPASSRLS tenant pool. Span decomposition and reassembly (05 §5.4 steps
// 1, 3, 4) and the review-queue seam are not here yet.
package dprelease
