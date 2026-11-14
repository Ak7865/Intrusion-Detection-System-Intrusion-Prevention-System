// settings/api-keys — Honest placeholder
export default function ApiKeysPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h3>API Keys</h3>
          <p className="b3 muted">Keys that authenticate IPS sensor nodes.</p>
        </div>
      </div>
      <div className="card" style={{ padding: 24 }}>
        <p className="b3 muted" style={{ marginBottom: 16 }}>
          IPS sensor nodes authenticate using SHA-256 hashed tokens configured
          in the server environment. The raw tokens are never exposed through
          this interface.
        </p>
        <ul className="b3 muted" style={{ paddingLeft: 20, lineHeight: "1.8em" }}>
          <li>
            Tokens are stored as hashes in{" "}
            <code>IPS_NODE_TOKEN_HASHES</code> in the server{" "}
            <code>.env</code> file.
          </li>
          <li>
            Each node uses its token in the{" "}
            <code>X-Node-Token</code> header when posting to{" "}
            <code>/flow</code> or <code>/suricata</code>.
          </li>
          <li>
            To rotate a token, generate a new secret, hash it with SHA-256, and
            update the <code>.env</code> file, then restart the IPS server.
          </li>
        </ul>
      </div>
    </>
  );
}

