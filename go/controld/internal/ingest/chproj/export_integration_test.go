//go:build integration

package chproj

// SetupCH hands the scratch-database harness to the chproj_test package next
// door, which is where an end-to-end ingest → Projector → ClickHouse test has
// to live: package chproj cannot import ingest (cycle), and no directory
// outside chproj/querychoke may import the ClickHouse driver to SELECT the
// row back (depguard clickhouse-choke, 13 §7.3). Gate: M1_TEST_CH_DSN.
var SetupCH = setupCH
