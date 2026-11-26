import sys

import db
from audit import log_event


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)

    username = sys.argv[1].strip().lower()
    conn = db.get_conn()
    user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        print("No such user.")
        sys.exit(1)

    conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user["id"],))
    log_event(conn, "role_changed", user_id=user["id"], detail="role=admin via local script")
    conn.commit()
    print(f"{username} is now an admin.")


if __name__ == "__main__":
    main()
