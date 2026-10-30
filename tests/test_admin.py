import copy
import json
import re

import httpx
import pytest

from guacamole_mcp_server import server
from guacamole_mcp_server.admin import _timestamp
from guacamole_mcp_server.api import GuacamoleAPI, GuacamoleError, GuacamolePermissionError

BASE = "https://guac.test/guacamole"
TREE = {
    "identifier": "ROOT", "name": "ROOT", "type": "ORGANIZATIONAL",
    "childConnections": [{"identifier": "17", "name": "STBWEB-07", "protocol": "rdp", "attributes": {}}],
    "childConnectionGroups": [{
        "identifier": "1", "name": "Clientes", "type": "ORGANIZATIONAL",
        "childConnectionGroups": [
            {"identifier": "2", "name": "Linux", "type": "ORGANIZATIONAL",
             "childConnections": [{"identifier": "650", "name": "L-24410-WEB-03", "protocol": "ssh", "attributes": {}}]},
            {"identifier": "3", "name": "Windows", "type": "ORGANIZATIONAL",
             "childConnections": [{"identifier": "419", "name": "W-24410-WEB-01", "protocol": "rdp",
                                   "attributes": {"winrm-enabled": "true"}}]},
            {"identifier": "4", "name": "Vazio", "type": "ORGANIZATIONAL"},
        ],
    }],
}
CONNECTIONS = {
    "650": {"identifier": "650", "name": "L-24410-WEB-03", "parentIdentifier": "2", "protocol": "ssh",
            "attributes": {"max-connections": "", "guacd-hostname": ""}, "activeConnections": 1, "lastActive": 1760000000000},
    "419": {"identifier": "419", "name": "W-24410-WEB-01", "parentIdentifier": "3", "protocol": "rdp",
            "attributes": {"winrm-enabled": "true", "winrm-port": "5985"}, "activeConnections": 0},
    "17": {"identifier": "17", "name": "STBWEB-07", "parentIdentifier": "ROOT", "protocol": "rdp", "attributes": {}},
}
PARAMETERS = {
    "650": {"hostname": "10.0.0.3", "port": "22", "username": "remops", "password": "s3cret",
            "private-key": "-----BEGIN KEY-----", "recording-path": "${HISTORY_PATH}/${HISTORY_UUID}"},
    "419": {"hostname": "10.0.0.9", "port": "3389", "username": "Administrator", "password": "w1n"},
}
HISTORY = [
    {"username": "ana", "remoteHost": "10.9.9.1", "startDate": 1760000000000, "endDate": 1760000600000, "connectionName": "L-24410-WEB-03"},
    {"username": "svc-mcp", "remoteHost": "10.9.9.2", "startDate": 1760100000000, "active": True, "connectionName": "L-24410-WEB-03"},
    {"username": "bia", "remoteHost": "10.9.9.3", "startDate": 1750000000000, "endDate": 1750000600000, "connectionName": "L-24410-WEB-03"},
]
USERS = {
    "svc-mcp": {"username": "svc-mcp", "disabled": False, "attributes": {"guac-full-name": "MCP"}},
    "joao": {"username": "joao", "disabled": False, "lastActive": 1760000000000,
             "attributes": {"guac-full-name": "João Silva", "guac-email-address": "joao@example.com",
                            "guac-totp-key-secret": "ABCDEF", "expired": "", "timezone": ""}},
    # Guacamole 1.5 and earlier: "disabled" is an attribute.
    "legado": {"username": "legado", "attributes": {"disabled": "", "guac-full-name": "Legado"}},
}
PERMISSIONS = {
    "joao": {"connectionPermissions": {"650": ["READ"], "999": ["READ"]}, "connectionGroupPermissions": {"3": ["READ"]},
             "userPermissions": {"joao": ["READ"]}, "systemPermissions": []},
}
EFFECTIVE = {
    "svc-mcp": {"systemPermissions": ["CREATE_CONNECTION"], "connectionPermissions": {"650": ["READ", "UPDATE"], "419": ["READ", "UPDATE"], "17": ["READ"]}},
    "joao": {"systemPermissions": ["CREATE_USER"], "connectionPermissions": {"650": ["READ"], "419": ["READ"]}},
}
USER_GROUPS = {"n2": {"identifier": "n2", "disabled": False, "attributes": {}}}
MEMBERS = {"n2": ["joao"]}


def denied(message="Permission denied."):
    return httpx.Response(403, json={"message": message, "type": "PERMISSION_DENIED"})


class FakeGuacamole:
    """In-memory Guacamole REST API (data source "mysql") recording every request."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, object]] = []
        self.logins = 0
        self.tokens: set[str] = set()
        self.connections = copy.deepcopy(CONNECTIONS)
        self.parameters = copy.deepcopy(PARAMETERS)
        self.users = copy.deepcopy(USERS)
        self.user_groups = copy.deepcopy(USER_GROUPS)
        self.members = copy.deepcopy(MEMBERS)

    def expire_tokens(self) -> None:
        self.tokens.clear()

    def writes(self) -> list[tuple[str, str, object]]:
        return [r for r in self.requests if r[0] != "GET"]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/guacamole/api")
        body = json.loads(request.content) if request.content and path != "/tokens" else None
        if path == "/tokens":
            self.logins += 1
            token = f"tok{self.logins}"
            self.tokens.add(token)
            return httpx.Response(200, json={"authToken": token, "username": "svc-mcp", "dataSource": "mysql",
                                             "availableDataSources": ["mysql", "mysql-shared"]})
        if request.headers.get("Guacamole-Token") not in self.tokens:
            return denied("Permission Denied.")
        self.requests.append((request.method, path, body))
        if path.startswith("/session/data/mysql-shared/"):
            return httpx.Response(404, json={"message": "Not found.", "type": "NOT_FOUND"})
        route = path.removeprefix("/session/data/mysql")
        return self.route(request.method, route, body)

    def route(self, method: str, route: str, body):
        if route == "/connectionGroups/ROOT/tree":
            return httpx.Response(200, json=TREE)
        if route == "/self":
            return httpx.Response(200, json=self.users["svc-mcp"])
        if route == "/self/effectivePermissions":
            return httpx.Response(200, json=EFFECTIVE["svc-mcp"])
        if route == "/self/userGroups":
            return httpx.Response(200, json=["n2"])
        if route == "/activeConnections":
            return httpx.Response(200, json={"a1": {"identifier": "a1", "connectionIdentifier": "650", "username": "ana",
                                                    "remoteHost": "10.9.9.1", "startDate": 1760000000000}})
        if route == "/connections" and method == "POST":
            return httpx.Response(200, json=body | {"identifier": "1000"})
        if route == "/connectionGroups" and method == "POST":
            return httpx.Response(200, json=body | {"identifier": "50"})
        if m := re.fullmatch(r"/connections/(\w+)(/\w+)?", route):
            ident, sub = m.groups()
            if ident not in self.connections:
                return httpx.Response(404, json={"message": "No such connection.", "type": "NOT_FOUND"})
            if sub == "/parameters":
                return httpx.Response(200, json=self.parameters[ident]) if ident in self.parameters else denied()
            if sub == "/history":
                return httpx.Response(200, json=HISTORY)
            if method == "PUT":
                return httpx.Response(204)
            if method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(200, json=self.connections[ident])
        if m := re.fullmatch(r"/connectionGroups/(\w+)", route):
            if method in ("PUT", "DELETE"):
                return httpx.Response(204)
            return httpx.Response(200, json={"identifier": m[1], "name": "Vazio", "parentIdentifier": "1",
                                             "type": "ORGANIZATIONAL", "attributes": {"max-connections": ""}})
        if route == "/users":
            if method == "POST":
                return httpx.Response(200, json=body)
            return httpx.Response(200, json=self.users)
        if m := re.fullmatch(r"/users/([^/]+)(/\w+)?", route):
            username, sub = m.groups()
            if username not in self.users:
                return httpx.Response(404, json={"message": f'No such user: "{username}"', "type": "NOT_FOUND"})
            if sub == "/permissions":
                return httpx.Response(204) if method == "PATCH" else httpx.Response(200, json=PERMISSIONS.get(username, {}))
            if sub == "/effectivePermissions":
                return httpx.Response(200, json=EFFECTIVE.get(username, {}))
            if sub == "/userGroups":
                return httpx.Response(200, json=[g for g, m in self.members.items() if username in m])
            if sub == "/history":
                return httpx.Response(200, json=HISTORY)
            if method in ("PUT", "DELETE"):
                return httpx.Response(204)
            return httpx.Response(200, json=self.users[username])
        if route == "/userGroups":
            if method == "POST":
                return httpx.Response(200, json=body)
            return httpx.Response(200, json=self.user_groups)
        if m := re.fullmatch(r"/userGroups/([^/]+)(/\w+)?", route):
            name, sub = m.groups()
            if name not in self.user_groups:
                return httpx.Response(404, json={"message": f'No such user group: "{name}"', "type": "NOT_FOUND"})
            if sub == "/memberUsers":
                if method == "PATCH":
                    for patch in body:  # unknown users are skipped, like Guacamole does
                        if patch["value"] in self.users:
                            members = self.members.setdefault(name, [])
                            if patch["op"] == "add" and patch["value"] not in members:
                                members.append(patch["value"])
                            elif patch["op"] == "remove" and patch["value"] in members:
                                members.remove(patch["value"])
                    return httpx.Response(204)
                return httpx.Response(200, json=self.members.get(name, []))
            if sub in ("/memberUserGroups", "/userGroups"):
                return httpx.Response(204) if method == "PATCH" else httpx.Response(200, json=[])
            if sub == "/permissions":
                return httpx.Response(204) if method == "PATCH" else httpx.Response(200, json={"connectionGroupPermissions": {"2": ["READ"]}})
            if method in ("PUT", "DELETE"):
                return httpx.Response(204)
            return httpx.Response(200, json=self.user_groups[name])
        return httpx.Response(404, json={"message": f"unexpected {method} {route}", "type": "NOT_FOUND"})


@pytest.fixture
def guac(monkeypatch):
    for name, value in (("GUACAMOLE_URL", BASE), ("GUACAMOLE_USERNAME", "svc-mcp"), ("GUACAMOLE_PASSWORD", "x")):
        monkeypatch.setenv(name, value)
    fake = FakeGuacamole()
    mgr = server.SessionManager(server.Settings())
    mgr.api = GuacamoleAPI(BASE, "svc-mcp", "x", transport=httpx.MockTransport(fake))
    monkeypatch.setattr(server, "manager", mgr)
    return fake


class FakeSession:
    is_open = True

    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


async def test_permission_denied_does_not_log_in_again(guac):
    with pytest.raises(GuacamolePermissionError, match="svc-mcp"):
        await server.manager.api.data("GET", "/connections/17/parameters")
    assert guac.logins == 1


async def test_expired_token_logs_in_again(guac):
    await server.list_users()
    guac.expire_tokens()
    assert [u["username"] for u in await server.list_users()] == ["joao", "legado", "svc-mcp"]
    assert guac.logins == 2


async def test_list_connections_still_lists_only_usable_ones(guac):
    assert [c["name"] for c in await server.list_connections()] == ["L-24410-WEB-03", "W-24410-WEB-01"]
    assert len(await server.list_connections(include_all=True)) == 3


async def test_current_user_shows_what_it_may_administer(guac):
    me = await server.get_current_user()
    assert me["username"] == "svc-mcp"
    assert me["administrator"] is False
    assert me["system_permissions"] == ["CREATE_CONNECTION"]
    assert me["objects_per_permission"] == {"connections": {"READ": 3, "UPDATE": 2}}
    assert me["data_source"] == "mysql" and me["user_groups"] == ["n2"]


async def test_get_connection_masks_secrets_and_sorts_history(guac):
    conn = await server.get_connection("WEB-03", history_limit=2)
    assert conn["group"] == "Clientes/Linux" and conn["parent_identifier"] == "2"
    assert conn["parameters"]["hostname"] == "10.0.0.3"
    assert conn["parameters"]["password"] == "***" and conn["parameters"]["private-key"] == "***"
    assert "attributes" not in conn  # only empty attributes: left out
    assert [h["username"] for h in conn["history"]] == ["svc-mcp", "ana"]
    assert "s3cret" not in json.dumps(conn)


async def test_get_connection_without_update_permission(guac):
    conn = await server.get_connection("STBWEB-07")
    assert conn["parameters"].startswith("not readable")
    assert conn["protocol"] == "rdp" and conn["group"] == "ROOT"


async def test_update_connection_merges_with_current_settings(guac):
    session = FakeSession()
    server.manager.sessions["mysql:650"] = session
    result = await server.update_connection("L-24410-WEB-03", parameters={"hostname": "10.0.0.4", "port": 2222, "private-key": None})
    put = [r for r in guac.writes() if r[0] == "PUT"]
    assert len(put) == 1
    _, path, body = put[0]
    assert path == "/session/data/mysql/connections/650"
    assert body["name"] == "L-24410-WEB-03" and body["parentIdentifier"] == "2" and body["protocol"] == "ssh"
    assert body["parameters"] == PARAMETERS["650"] | {"hostname": "10.0.0.4", "port": "2222", "private-key": ""}
    assert body["attributes"] == CONNECTIONS["650"]["attributes"]
    assert result["parameters"] == {"hostname": "10.0.0.4", "port": "2222", "private-key": "(cleared)"}
    assert session.closed and "mysql:650" not in server.manager.sessions


async def test_update_connection_moves_and_sets_attributes(guac):
    await server.update_connection("W-24410-WEB-01", group="Clientes/Linux", attributes={"winrm-enabled": False})
    _, _, body = guac.writes()[0]
    assert body["parentIdentifier"] == "2"
    assert body["attributes"] == {"winrm-enabled": "", "winrm-port": "5985"}
    assert body["parameters"]["password"] == "w1n"


async def test_changes_refuse_the_mask_and_partial_names(guac):
    with pytest.raises(GuacamoleError, match="mask"):
        await server.update_connection("L-24410-WEB-03", parameters={"password": "***"})
    with pytest.raises(GuacamoleError, match="exact"):
        await server.update_connection("WEB-03", name="x")
    with pytest.raises(GuacamoleError, match="exact"):
        await server.delete_connection("WEB-03")
    with pytest.raises(GuacamoleError, match="Nothing to change"):
        await server.update_connection("L-24410-WEB-03")
    assert guac.writes() == []


async def test_create_connection_in_group_path(guac):
    result = await server.create_connection(
        "L-24410-DB-01", "ssh", {"hostname": "10.0.0.5", "port": 22, "username": "remops", "password": "p"},
        group="Clientes/Linux", attributes={"max-connections": 2},
    )
    method, path, body = guac.writes()[0]
    assert (method, path) == ("POST", "/session/data/mysql/connections")
    assert body == {"parentIdentifier": "2", "name": "L-24410-DB-01", "protocol": "ssh",
                    "parameters": {"hostname": "10.0.0.5", "port": "22", "username": "remops", "password": "p"},
                    "attributes": {"max-connections": "2"}}
    assert result == {"created": "Clientes/Linux/L-24410-DB-01", "identifier": "1000", "protocol": "ssh", "data_source": "mysql"}
    with pytest.raises(GuacamoleError, match="No connection group"):
        await server.create_connection("x", "ssh", {}, group="Linu")


async def test_connection_groups(guac):
    groups = await server.list_connection_groups()
    assert [g["path"] for g in groups] == ["ROOT", "Clientes", "Clientes/Linux", "Clientes/Vazio", "Clientes/Windows"]
    with pytest.raises(GuacamoleError, match="deletes everything inside"):
        await server.delete_connection_group("Clientes/Linux")
    with pytest.raises(GuacamoleError, match="ROOT"):
        await server.delete_connection_group("ROOT")
    with pytest.raises(GuacamoleError, match="into itself"):
        await server.update_connection_group("Clientes", parent="Clientes/Linux")
    assert guac.writes() == []
    assert await server.delete_connection_group("Vazio") == {"deleted": "Clientes/Vazio", "identifier": "4"}
    await server.update_connection_group("Clientes/Vazio", parent="ROOT")
    _, _, body = guac.writes()[-1]
    assert body == {"parentIdentifier": "ROOT", "name": "Vazio", "type": "ORGANIZATIONAL", "attributes": {"max-connections": ""}}
    created = await server.create_connection_group("24410 - ACME", parent="Clientes/Linux")
    assert created == {"created": "Clientes/Linux/24410 - ACME", "identifier": "50", "type": "ORGANIZATIONAL"}


async def test_get_user_names_permissions_and_masks_secrets(guac):
    user = await server.get_user("joao", include_effective=True)
    assert user["full_name"] == "João Silva" and user["disabled"] is False
    assert user["attributes"] == {"guac-totp-key-secret": "***"}
    assert user["user_groups"] == ["n2"]
    assert user["permissions"]["connections"] == {
        "Clientes/Linux/L-24410-WEB-03 (id 650)": ["READ"], "not visible (id 999)": ["READ"],
    }
    assert user["permissions"]["connection_groups"] == {"Clientes/Windows (id 3)": ["READ"]}
    assert user["effective_system_permissions"] == ["CREATE_USER"]
    assert len(user["effective_permissions"]["connections"]) == 2
    assert "ABCDEF" not in json.dumps(user)
    with pytest.raises(GuacamoleError, match="No such user"):
        await server.get_user("ninguem")


async def test_update_user_keeps_what_was_not_given(guac):
    await server.update_user("joao", attributes={"guac-email-address": "j@example.com"})
    _, path, body = guac.writes()[0]
    assert path == "/session/data/mysql/users/joao"
    assert body["disabled"] is False and "password" not in body
    assert body["attributes"] == USERS["joao"]["attributes"] | {"guac-email-address": "j@example.com"}
    await server.update_user("joao", disabled=True, password="nova")
    _, _, body = guac.writes()[1]
    assert body["disabled"] is True and body["password"] == "nova"
    # Guacamole 1.5: disabled is an attribute.
    await server.update_user("legado", disabled=True)
    _, _, body = guac.writes()[2]
    assert "disabled" not in body and body["attributes"]["disabled"] == "true"


async def test_users_refuse_self_lockout_and_bad_passwords(guac):
    with pytest.raises(GuacamoleError, match="logs in with"):
        await server.delete_user("svc-mcp")
    with pytest.raises(GuacamoleError, match="logs in with"):
        await server.update_user("svc-mcp", disabled=True)
    with pytest.raises(GuacamoleError, match="actual password"):
        await server.create_user("maria", password="")
    with pytest.raises(GuacamoleError, match="actual password"):
        await server.update_user("joao", password="***")
    assert guac.writes() == []
    assert await server.create_user("maria", attributes={"guac-full-name": "Maria", "expired": True}) == {"created": "maria", "password": "none"}
    assert guac.writes()[0][2] == {"username": "maria", "attributes": {"guac-full-name": "Maria", "expired": "true"}}


async def test_update_permissions_builds_one_patch(guac):
    result = await server.update_permissions(target_type="connection", target="L-24410-WEB-03", grant=["READ"], user="joao")
    assert guac.writes() == [("PATCH", "/session/data/mysql/users/joao/permissions",
                              [{"op": "add", "path": "/connectionPermissions/650", "value": "READ"}])]
    assert result == {"user": "joao", "target_type": "connection", "target": "Clientes/Linux/L-24410-WEB-03", "granted": ["READ"]}
    await server.update_permissions(target_type="connection_group", target="Clientes/Windows", grant=["READ"], revoke=["UPDATE"], user_group="n2")
    assert guac.writes()[1] == ("PATCH", "/session/data/mysql/userGroups/n2/permissions", [
        {"op": "add", "path": "/connectionGroupPermissions/3", "value": "READ"},
        {"op": "remove", "path": "/connectionGroupPermissions/3", "value": "UPDATE"},
    ])
    await server.update_permissions(target_type="system", grant=["CREATE_USER"], user="joao")
    assert guac.writes()[2][2] == [{"op": "add", "path": "/systemPermissions", "value": "CREATE_USER"}]


async def test_update_permissions_validates_before_patching(guac):
    cases = [
        (dict(target_type="system", grant=["READ"], user="joao"), "cannot be used"),
        (dict(target_type="connection", target="L-24410-WEB-03", grant=["CREATE_USER"], user="joao"), "cannot be used"),
        (dict(target_type="connection", target="L-24410-WEB-03", grant=["READ"]), "exactly one"),
        (dict(target_type="connection", target="L-24410-WEB-03", grant=["READ"], user="joao", user_group="n2"), "exactly one"),
        (dict(target_type="connection", grant=["READ"], user="joao"), "target"),
        (dict(target_type="system", target="x", grant=["AUDIT"], user="joao"), "no target"),
        (dict(target_type="connection", target="WEB-03", grant=["READ"], user="joao"), "exact"),
        (dict(target_type="user", target="ninguem", grant=["READ"], user="joao"), "No such user"),
        (dict(target_type="connection", target="L-24410-WEB-03", grant=["READ"], user="ninguem"), "No such user"),
        (dict(target_type="connection", target="L-24410-WEB-03", grant=["READ"], revoke=["READ"], user="joao"), "both"),
    ]
    for kwargs, message in cases:
        with pytest.raises(GuacamoleError, match=message):
            await server.update_permissions(**kwargs)
    assert guac.writes() == []


async def test_group_members_reports_what_was_not_applied(guac):
    result = await server.update_group_members("n2", add_users=["legado", "ninguem"], remove_users=["joao"])
    assert result == {"group": "n2", "member_users": ["legado"], "not_applied": ["ninguem"]}
    group = await server.get_user_group("n2")
    assert group["member_users"] == ["legado"]
    assert group["permissions"] == {"connection_groups": {"Clientes/Linux (id 2)": ["READ"]}}


async def test_user_group_disable_keeps_attributes(guac):
    await server.update_user_group("n2", disabled=True)
    assert guac.writes()[0] == ("PUT", "/session/data/mysql/userGroups/n2", {"identifier": "n2", "attributes": {}, "disabled": True})


async def test_active_connections_are_named(guac):
    assert await server.list_active_connections("ana") == [{
        "identifier": "a1", "connection": "Clientes/Linux/L-24410-WEB-03", "connection_identifier": "650",
        "username": "ana", "remote_host": "10.9.9.1", "started": _timestamp(1760000000000), "data_source": "mysql",
    }]
