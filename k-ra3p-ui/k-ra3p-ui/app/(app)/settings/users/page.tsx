// settings/users — Honest placeholder (no user management API)
export default function UsersPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h3>Users</h3>
          <p className="b3 muted">Admin Panel access control.</p>
        </div>
      </div>
      <div className="card" style={{ padding: 24 }}>
        <p className="b3 muted">
          The IPS API uses pre-shared node token hashes (defined in{" "}
          <code>integration/windows_ml_service/.env</code>) for sensor
          authentication. There is no user account management endpoint in the
          current API version. User access to this Admin Panel is controlled at
          the network/firewall level.
        </p>
      </div>
    </>
  );
}
