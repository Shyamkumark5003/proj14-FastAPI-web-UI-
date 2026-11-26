# Access control test matrix

Roles: `anonymous`, `user`, `admin`. "Own" is a record the caller owns. "Other" is a record owned by a different user.
The matrix is enforced by `tests/test_access_matrix.py`, which also checks that a new route cannot be added without a row here.

| Endpoint | Anonymous | User, own | User, other | Admin, own | Admin, other |
|---|---|---|---|---|---|
| POST /records | 401 | 201 | n/a | 201 | n/a |
| GET /records (own list) | 401 | 200 | n/a | 200 | n/a |
| GET /records/{id} | 401 | 200 | 404 | 200 | 200, audited |
| DELETE /records/{id} | 401 | 204 | 404 | 204 | 404 |
| GET /admin/users | 401 | 403 | n/a | 200 | n/a |

## Rules behind the matrix

1. Authentication first: no valid session gives 401.
2. RBAC second: the role must hold the permission, otherwise 403. All role checks live in `rbac.py`.
3. Ownership third: someone else's record gives 404, the same answer as a record that does not exist, so record ids cannot be probed.
4. An admin may read any record (`records:read_any`), and every such read is audited as `record_access_other`.
5. An admin may not delete other users' records (least privilege).
6. The owner of a new record always comes from the session, never from the request body.
7. Denied requests never return the record content.

## Audit events

`ownership_denied`, `access_denied`, `record_access_other`, `record_created`, `record_deleted`.
