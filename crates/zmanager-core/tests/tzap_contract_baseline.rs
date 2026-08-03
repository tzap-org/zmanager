use serde_json::Value;

#[test]
fn normative_wire_fixture_preserves_current_protocol_anchors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/tzap-normative-wire-anchors.json"
    ))
    .expect("normative TZAP fixture must be valid JSON");

    assert_eq!(
        fixture["contractVersion"],
        "local-inventory-consolidation/v1"
    );
    assert_eq!(
        fixture["nativeAuthExchange"]["path"],
        "/auth/session/exchange"
    );
    assert_eq!(fixture["bulkStatus"]["responseField"], "responses");
    assert_eq!(fixture["denial"]["statusClass"], "non-2xx");
    assert_eq!(fixture["enrollment"]["signatureEncoding"], "P1363");
}
