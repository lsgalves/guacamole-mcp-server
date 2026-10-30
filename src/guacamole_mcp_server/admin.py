"""Administration of Guacamole connections, connection groups, users, user groups and permissions.

Every call goes to the REST API as the configured user, so Guacamole itself decides what is
allowed: system permissions (ADMINISTER, CREATE_*) and UPDATE / DELETE / ADMINISTER on each
object. What the user may not do is refused with HTTP 403 (GuacamolePermissionError).

Guacamole replaces the whole object on PUT (parameters, attributes, disabled), so updates read
the current object and merge only the fields that were given.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import quote

from .api import ConnectionGroup, GuacamoleAPI, GuacamoleError, GuacamolePermissionError

if TYPE_CHECKING:
    from .server import SessionManager

# Connection parameters and user attributes holding secrets (passwords, SSH/Kubernetes keys,
# TOTP secret, Keeper configuration): shown masked and refused as input.
SECRET_KEY = re.compile(r"password|passphrase|private-key|client-key|secret|token|ksm-user-config", re.IGNORECASE)
REDACTED = "***"

OBJECT_PERMISSIONS = ("READ", "UPDATE", "DELETE", "ADMINISTER")
SYSTEM_PERMISSIONS = (
    "ADMINISTER", "AUDIT", "CREATE_USER", "CREATE_USER_GROUP", "CREATE_CONNECTION",
    "CREATE_CONNECTION_GROUP", "CREATE_SHARING_PROFILE",
)
# Target type -> key in Guacamole permission sets (also the PATCH path prefix).
PERMISSION_SETS = {
    "connection": "connectionPermissions",
    "connection_group": "connectionGroupPermissions",
    "user": "userPermissions",
    "user_group": "userGroupPermissions",
}
USER_FIELDS = {
    "full_name": "guac-full-name",
    "email": "guac-email-address",
    "organization": "guac-organization",
    "role": "guac-organizational-role",
}
NOTE_PERMISSIONS = (
    "Guacamole refuses (HTTP 403) what these permissions do not allow: creating needs ADMINISTER or "
    "the matching CREATE_*, changing or deleting an object needs ADMINISTER or UPDATE/DELETE on it, "
    "and granting permissions on an object needs ADMINISTER on it."
)


class GuacamoleAdmin:
    def __init__(self, manager: SessionManager) -> None:
        self.manager = manager

    @property
    def api(self) -> GuacamoleAPI:
        return self.manager.api

    # Reads.

    async def current_user(self) -> dict:
        ds = await self.api.default_data_source()
        me = await self.api.data("GET", "/self")
        effective = await self.api.data("GET", "/self/effectivePermissions") or {}
        groups = await self.api.data("GET", "/self/userGroups") or []
        system = sorted(effective.get("systemPermissions") or [])
        counts = {
            label: _count(effective.get(key))
            for label, key in (("connections", "connectionPermissions"),
                               ("connection_groups", "connectionGroupPermissions"),
                               ("users", "userPermissions"), ("user_groups", "userGroupPermissions"))
            if effective.get(key)
        }
        return {
            **_user(me),
            "data_source": ds,
            "data_sources": self.api.data_sources,
            "user_groups": sorted(groups),
            "administrator": "ADMINISTER" in system,
            "system_permissions": system,
            "objects_per_permission": counts,
            "note": NOTE_PERMISSIONS,
        }

    async def connection(self, query: str, history_limit: int = 10) -> dict:
        conn = await self.manager.resolve(query, usable_only=False)
        ds, base = conn.data_source, f"/connections/{_seg(conn.identifier)}"
        info = await self.api.data("GET", base, data_source=ds)
        try:
            parameters: dict | str = _clean(await self.api.data("GET", f"{base}/parameters", data_source=ds))
        except GuacamolePermissionError:
            parameters = "not readable: needs UPDATE permission on the connection"
        try:
            history = await self.api.data("GET", f"{base}/history", data_source=ds)
        except GuacamolePermissionError:
            history = []
        return _compact({
            **conn.to_dict(),
            "parent_identifier": info.get("parentIdentifier"),
            "parameters": parameters,
            "attributes": _clean(info.get("attributes")),
            "active_connections": info.get("activeConnections"),
            "last_active": _timestamp(info.get("lastActive")),
            "history": [_record(r) for r in _latest(history, history_limit)],
        })

    async def connection_groups(self, search: str | None = None) -> list[dict]:
        groups = await self.manager.groups(refresh=True)
        if search:
            groups = [g for g in groups if search.lower() in (g.path or "ROOT").lower()]
        return [g.to_dict() for g in sorted(groups, key=lambda g: (g.data_source, g.path.lower()))]

    async def active_connections(self, search: str | None = None) -> list[dict]:
        names = {(c.data_source, c.identifier): c.full_name for c in await self.manager.connections()}
        rows = []
        for ds in self.api.data_sources:
            try:
                active = await self.api.data("GET", "/activeConnections", data_source=ds) or {}
            except GuacamoleError:
                continue  # e.g. data sources without connections
            for a in active.values():
                connection_id = str(a.get("connectionIdentifier"))
                rows.append(_compact({
                    "identifier": a.get("identifier"),
                    "connection": names.get((ds, connection_id), f"id {connection_id}"),
                    "connection_identifier": connection_id,
                    "username": a.get("username"),
                    "remote_host": a.get("remoteHost"),
                    "started": _timestamp(a.get("startDate")),
                    "data_source": ds,
                    "_start": a.get("startDate") or 0,
                }))
        if search:
            s = search.lower()
            rows = [r for r in rows if s in r["connection"].lower() or s in str(r.get("username", "")).lower()]
        rows.sort(key=lambda r: r["_start"], reverse=True)
        return [{k: v for k, v in r.items() if k != "_start"} for r in rows]

    async def users(self, search: str | None = None) -> list[dict]:
        rows = [_user(u) for u in (await self.api.data("GET", "/users") or {}).values()]
        if search:
            s = search.lower()
            rows = [r for r in rows if any(s in str(r.get(k, "")).lower() for k in ("username", *USER_FIELDS))]
        return sorted(rows, key=lambda r: str(r.get("username", "")).lower())

    async def user(self, username: str, history_limit: int = 10, include_effective: bool = False) -> dict:
        base = f"/users/{_seg(username)}"
        user = await self.api.data("GET", base)
        permissions = await self.api.data("GET", f"{base}/permissions") or {}
        effective = await self.api.data("GET", f"{base}/effectivePermissions") or {}
        groups = await self.api.data("GET", f"{base}/userGroups") or []
        try:
            history = await self.api.data("GET", f"{base}/history")
        except GuacamolePermissionError:
            history = []
        summarized = {*USER_FIELDS.values(), "disabled", "expired"}
        result = {
            **_user(user),
            "attributes": {k: v for k, v in _clean(user.get("attributes")).items() if k not in summarized},
            "user_groups": sorted(groups),
            "permissions": await self._describe(permissions),
            "effective_system_permissions": sorted(effective.get("systemPermissions") or []),
            "recent_logins": [_record(r) for r in _latest(history, history_limit)],
        }
        if include_effective:
            result["effective_permissions"] = await self._describe(effective)
        return _compact(result)

    async def user_groups(self, search: str | None = None) -> list[dict]:
        groups = (await self.api.data("GET", "/userGroups") or {}).values()
        rows = [{"name": g.get("identifier"), "disabled": _disabled(g)} for g in groups]
        if search:
            rows = [r for r in rows if search.lower() in str(r["name"]).lower()]
        return sorted(rows, key=lambda r: str(r["name"]).lower())

    async def user_group(self, name: str) -> dict:
        base = f"/userGroups/{_seg(name)}"
        group = await self.api.data("GET", base)
        return _compact({
            "name": group.get("identifier", name),
            "disabled": _disabled(group),
            "attributes": {k: v for k, v in _clean(group.get("attributes")).items() if k != "disabled"},
            "member_users": sorted(await self.api.data("GET", f"{base}/memberUsers") or []),
            "member_groups": sorted(await self.api.data("GET", f"{base}/memberUserGroups") or []),
            "parent_groups": sorted(await self.api.data("GET", f"{base}/userGroups") or []),
            "permissions": await self._describe(await self.api.data("GET", f"{base}/permissions") or {}),
        })

    # Connections and connection groups.

    async def create_connection(
        self, name: str, protocol: str, parameters: dict, group: str = "ROOT", attributes: dict | None = None
    ) -> dict:
        ds = await self.api.default_data_source()
        parent = await self._group(group, ds, exact=True)
        created = await self.api.data("POST", "/connections", {
            "parentIdentifier": parent.identifier,
            "name": name,
            "protocol": protocol,
            "parameters": _merge({}, parameters),
            "attributes": _merge({}, attributes),
        }) or {}
        self.manager.invalidate()
        return {
            "created": f"{parent.path}/{name}" if parent.path else name,
            "identifier": created.get("identifier"),
            "protocol": protocol,
            "data_source": ds,
        }

    async def update_connection(
        self,
        query: str,
        name: str | None = None,
        group: str | None = None,
        parameters: dict | None = None,
        attributes: dict | None = None,
    ) -> dict:
        if name is None and group is None and not parameters and not attributes:
            raise GuacamoleError("Nothing to change: pass name, group, parameters or attributes.")
        conn = await self.manager.resolve(query, usable_only=False, exact=True)
        ds, base = conn.data_source, f"/connections/{_seg(conn.identifier)}"
        current = await self.api.data("GET", base, data_source=ds)
        current_parameters = await self.api.data("GET", f"{base}/parameters", data_source=ds) or {}
        parent = await self._group(group, ds, exact=True) if group is not None else None
        await self.api.data("PUT", base, {
            "parentIdentifier": parent.identifier if parent else current.get("parentIdentifier"),
            "name": name or current.get("name"),
            "protocol": current.get("protocol"),
            "parameters": _merge(current_parameters, parameters),
            "attributes": _merge(current.get("attributes"), attributes),
        }, data_source=ds)
        await self.manager.close(conn)  # an open session would keep using the old settings
        self.manager.invalidate()
        return _compact({
            "updated": conn.full_name,
            "identifier": conn.identifier,
            "name": name,
            "group": (parent.path or "ROOT") if parent else None,
            "parameters": _changes(parameters),
            "attributes": _changes(attributes),
        })

    async def delete_connection(self, query: str) -> dict:
        conn = await self.manager.resolve(query, usable_only=False, exact=True)
        await self.api.data("DELETE", f"/connections/{_seg(conn.identifier)}", data_source=conn.data_source)
        await self.manager.close(conn)
        self.manager.invalidate()
        return {"deleted": conn.full_name, "identifier": conn.identifier}

    async def create_connection_group(
        self, name: str, parent: str = "ROOT", type: str = "ORGANIZATIONAL", attributes: dict | None = None
    ) -> dict:
        ds = await self.api.default_data_source()
        parent_group = await self._group(parent, ds, exact=True)
        created = await self.api.data("POST", "/connectionGroups", {
            "parentIdentifier": parent_group.identifier,
            "name": name,
            "type": type,
            "attributes": _merge({}, attributes),
        }) or {}
        self.manager.invalidate()
        return {
            "created": f"{parent_group.path}/{name}" if parent_group.path else name,
            "identifier": created.get("identifier"),
            "type": type,
        }

    async def update_connection_group(
        self, query: str, name: str | None = None, parent: str | None = None, attributes: dict | None = None
    ) -> dict:
        if name is None and parent is None and not attributes:
            raise GuacamoleError("Nothing to change: pass name, parent or attributes.")
        ds = await self.api.default_data_source()
        group = await self._group(query, ds, exact=True)
        if group.identifier == "ROOT":
            raise GuacamoleError("ROOT cannot be renamed or moved.")
        new_parent = await self._group(parent, ds, exact=True) if parent is not None else None
        if new_parent and (new_parent.path + "/").startswith(group.path + "/"):
            raise GuacamoleError(f"'{new_parent.path}' is inside '{group.path}': a group cannot be moved into itself.")
        base = f"/connectionGroups/{_seg(group.identifier)}"
        current = await self.api.data("GET", base)
        await self.api.data("PUT", base, {
            "parentIdentifier": new_parent.identifier if new_parent else current.get("parentIdentifier"),
            "name": name or current.get("name"),
            "type": current.get("type", "ORGANIZATIONAL"),
            "attributes": _merge(current.get("attributes"), attributes),
        })
        self.manager.invalidate()
        return _compact({
            "updated": group.path,
            "identifier": group.identifier,
            "name": name,
            "parent": (new_parent.path or "ROOT") if new_parent else None,
            "attributes": _changes(attributes),
        })

    async def delete_connection_group(self, query: str) -> dict:
        ds = await self.api.default_data_source()
        self.manager.invalidate()  # count the children on a fresh tree
        group = await self._group(query, ds, exact=True)
        if group.identifier == "ROOT":
            raise GuacamoleError("ROOT cannot be deleted.")
        if group.connections or group.groups:
            raise GuacamoleError(
                f"'{group.path}' has {group.connections} connection(s) and {group.groups} group(s): deleting a group "
                "deletes everything inside it. Move or delete them first."
            )
        await self.api.data("DELETE", f"/connectionGroups/{_seg(group.identifier)}")
        self.manager.invalidate()
        return {"deleted": group.path, "identifier": group.identifier}

    # Users and user groups.

    async def create_user(self, username: str, password: str | None = None, attributes: dict | None = None) -> dict:
        body = {"username": username, "attributes": _merge({}, attributes)}
        if password is not None:
            body["password"] = _password(password)
        await self.api.data("POST", "/users", body)
        return {"created": username, "password": "set" if password is not None else "none"}

    async def update_user(
        self,
        username: str,
        password: str | None = None,
        disabled: bool | None = None,
        attributes: dict | None = None,
    ) -> dict:
        if password is None and disabled is None and not attributes:
            raise GuacamoleError("Nothing to change: pass password, disabled or attributes.")
        if disabled and username == self.api.username:
            raise GuacamoleError(f"'{username}' is the user this MCP server logs in with; disable it in the Guacamole UI.")
        base = f"/users/{_seg(username)}"
        current = await self.api.data("GET", base)
        body = {"username": current.get("username", username), "attributes": _merge(current.get("attributes"), attributes)}
        _set_disabled(body, current, disabled)
        if password is not None:
            body["password"] = _password(password)
        await self.api.data("PUT", base, body)
        return _compact({
            "updated": username,
            "password": "changed" if password is not None else None,
            "disabled": disabled,
            "attributes": _changes(attributes),
        })

    async def delete_user(self, username: str) -> dict:
        if username == self.api.username:
            raise GuacamoleError(f"'{username}' is the user this MCP server logs in with; delete it in the Guacamole UI.")
        await self.api.data("DELETE", f"/users/{_seg(username)}")
        return {"deleted": username}

    async def create_user_group(self, name: str, attributes: dict | None = None) -> dict:
        await self.api.data("POST", "/userGroups", {"identifier": name, "attributes": _merge({}, attributes)})
        return {"created": name}

    async def update_user_group(self, name: str, disabled: bool | None = None, attributes: dict | None = None) -> dict:
        if disabled is None and not attributes:
            raise GuacamoleError("Nothing to change: pass disabled or attributes.")
        base = f"/userGroups/{_seg(name)}"
        current = await self.api.data("GET", base)
        body = {"identifier": current.get("identifier", name), "attributes": _merge(current.get("attributes"), attributes)}
        _set_disabled(body, current, disabled)
        await self.api.data("PUT", base, body)
        return _compact({"updated": name, "disabled": disabled, "attributes": _changes(attributes)})

    async def delete_user_group(self, name: str) -> dict:
        await self.api.data("DELETE", f"/userGroups/{_seg(name)}")
        return {"deleted": name}

    async def update_group_members(
        self,
        name: str,
        add_users: list[str] | None = None,
        remove_users: list[str] | None = None,
        add_groups: list[str] | None = None,
        remove_groups: list[str] | None = None,
    ) -> dict:
        if not (add_users or remove_users or add_groups or remove_groups):
            raise GuacamoleError("Nothing to change: pass add_users, remove_users, add_groups or remove_groups.")
        base = f"/userGroups/{_seg(name)}"
        await self.api.data("GET", base)  # a missing group fails here, with its name
        for path, add, remove in (("memberUsers", add_users, remove_users), ("memberUserGroups", add_groups, remove_groups)):
            if add or remove:
                await self.api.data("PATCH", f"{base}/{path}", _patch("/", add, remove))
        users = sorted(await self.api.data("GET", f"{base}/memberUsers") or [])
        groups = sorted(await self.api.data("GET", f"{base}/memberUserGroups") or [])
        # Guacamole silently skips names that do not exist.
        not_applied = sorted(
            {u for u in add_users or [] if u not in users} | {u for u in remove_users or [] if u in users}
            | {g for g in add_groups or [] if g not in groups} | {g for g in remove_groups or [] if g in groups}
        )
        return _compact({"group": name, "member_users": users, "member_groups": groups, "not_applied": not_applied})

    # Permissions.

    async def update_permissions(
        self,
        target_type: str,
        target: str | None = None,
        grant: list[str] | None = None,
        revoke: list[str] | None = None,
        user: str | None = None,
        user_group: str | None = None,
    ) -> dict:
        if (user is None) == (user_group is None):
            raise GuacamoleError("Pass exactly one of user or user_group: whose permissions change.")
        grant = [p.upper() for p in grant or []]
        revoke = [p.upper() for p in revoke or []]
        if not grant and not revoke:
            raise GuacamoleError("Nothing to change: pass grant or revoke.")
        if set(grant) & set(revoke):
            raise GuacamoleError(f"{sorted(set(grant) & set(revoke))} is both granted and revoked.")
        if target_type == "system":
            if target:
                raise GuacamoleError("System permissions have no target: leave target out.")
            valid, path, label = SYSTEM_PERMISSIONS, "/systemPermissions", None
        elif target_type in PERMISSION_SETS:
            if not target:
                raise GuacamoleError(f"Pass the {target_type} in target.")
            valid = OBJECT_PERMISSIONS
            identifier, label = await self._target(target_type, target)
            path = f"/{PERMISSION_SETS[target_type]}/{identifier}"
        else:
            raise GuacamoleError(f"Unknown target_type '{target_type}': use system or {', '.join(PERMISSION_SETS)}.")
        invalid = [p for p in grant + revoke if p not in valid]
        if invalid:
            raise GuacamoleError(f"{invalid} cannot be used with target_type {target_type}: use {', '.join(valid)}.")
        principal = f"/users/{_seg(user)}" if user is not None else f"/userGroups/{_seg(user_group or '')}"
        await self.api.data("GET", principal)  # a missing user or group fails here, with its name
        await self.api.data("PATCH", f"{principal}/permissions", _patch(path, grant, revoke))
        return _compact({
            "user": user,
            "user_group": user_group,
            "target_type": target_type,
            "target": label,
            "granted": grant,
            "revoked": revoke,
        })

    # Helpers.

    async def _target(self, target_type: str, target: str) -> tuple[str, str]:
        """Identifier and display name of a permission target in the primary data source."""
        ds = await self.api.default_data_source()
        if target_type == "connection":
            conn = await self.manager.resolve(target, usable_only=False, exact=True)
            if conn.data_source != ds:
                raise GuacamoleError(f"'{conn.full_name}' is in data source '{conn.data_source}', not '{ds}'.")
            return conn.identifier, conn.full_name
        if target_type == "connection_group":
            group = await self._group(target, ds, exact=True)
            return group.identifier, group.path or "ROOT"
        # Users and user groups are identified by name; a missing one fails here.
        await self.api.data("GET", f"/{'users' if target_type == 'user' else 'userGroups'}/{_seg(target)}")
        return target, target

    async def _group(self, query: str, ds: str, exact: bool = False) -> ConnectionGroup:
        q = query.strip().strip("/").lower()
        if q in ("", "root"):
            return ConnectionGroup("ROOT", "ROOT", "ORGANIZATIONAL", ds)
        for refresh in (False, True):
            groups = [g for g in await self.manager.groups(refresh) if g.data_source == ds and g.identifier != "ROOT"]
            for matcher in (
                lambda g: g.identifier == query.strip(),
                lambda g: g.path.lower() == q,
                lambda g: g.name.lower() == q,
            ):
                hits = [g for g in groups if matcher(g)]
                if len(hits) == 1:
                    return hits[0]
                if len(hits) > 1:
                    raise GuacamoleError(_ambiguous_groups(query, hits))
            if not exact:
                hits = [g for g in groups if q in g.path.lower()]
                if len(hits) == 1:
                    return hits[0]
                if len(hits) > 1:
                    raise GuacamoleError(_ambiguous_groups(query, hits))
        hint = " (use the exact path, name or identifier)" if exact else ""
        raise GuacamoleError(f"No connection group matches '{query}'{hint}. Use list_connection_groups to see them.")

    async def _describe(self, permissions: dict) -> dict:
        """Permission set with connection and group identifiers turned into names."""
        ds = await self.api.default_data_source()
        connections = {c.identifier: c.full_name for c in await self.manager.connections() if c.data_source == ds}
        groups = {g.identifier: g.path or "ROOT" for g in await self.manager.groups() if g.data_source == ds}
        out: dict = {}
        if permissions.get("systemPermissions"):
            out["system"] = sorted(permissions["systemPermissions"])
        for label, key, names in (
            ("connections", "connectionPermissions", connections),
            ("connection_groups", "connectionGroupPermissions", groups),
            ("users", "userPermissions", None),
            ("user_groups", "userGroupPermissions", None),
            ("sharing_profiles", "sharingProfilePermissions", None),
        ):
            entries = permissions.get(key) or {}
            if entries:
                out[label] = dict(sorted(
                    (f"{names.get(i, 'not visible')} (id {i})" if names is not None else i, sorted(p))
                    for i, p in entries.items()
                ))
        return out


def _seg(value: str) -> str:
    """Quote a name for use as one URL path segment."""
    return quote(value, safe="")


def _timestamp(ms) -> str | None:
    return datetime.fromtimestamp(ms / 1000).astimezone().isoformat(timespec="seconds") if ms else None


def _compact(values: dict) -> dict:
    return {k: v for k, v in values.items() if v is not None and v != "" and v != [] and v != {}}


def _clean(values: dict | None) -> dict:
    """Parameters/attributes without empty values, secrets masked."""
    return {k: REDACTED if SECRET_KEY.search(k) else v for k, v in sorted((values or {}).items()) if v not in (None, "")}


def _changes(values: dict | None) -> dict | None:
    """The requested changes as shown back: secrets masked, cleared values marked."""
    if not values:
        return None
    return {
        k: "(cleared)" if v is None or v == "" or v is False else REDACTED if SECRET_KEY.search(k) else _value(v)
        for k, v in values.items()
    }


def _value(value) -> str:
    # Guacamole stores every parameter/attribute as a string; booleans are "true" or empty.
    if isinstance(value, bool):
        return "true" if value else ""
    return str(value)


def _merge(current: dict | None, changes: dict | None) -> dict:
    """Apply changes to a parameter/attribute map; None or False clears the value."""
    merged = dict(current or {})
    for key, value in (changes or {}).items():
        if value == REDACTED:
            raise GuacamoleError(
                f"'{key}' is '{REDACTED}', the mask shown in place of secrets: pass the real value or leave it out."
            )
        merged[key] = "" if value is None else _value(value)
    return merged


def _password(password: str) -> str:
    if not password or password == REDACTED:
        raise GuacamoleError("Pass the actual password (not empty, not the mask).")
    return password


def _set_disabled(body: dict, current: dict, disabled: bool | None) -> None:
    # Guacamole 1.6 has a "disabled" property; earlier versions keep it as an attribute.
    if "disabled" in current:
        body["disabled"] = current["disabled"] if disabled is None else disabled
    elif disabled is not None:
        body["attributes"]["disabled"] = "true" if disabled else ""


def _disabled(obj: dict) -> bool:
    if "disabled" in obj:
        return bool(obj["disabled"])
    return (obj.get("attributes") or {}).get("disabled") == "true"


def _user(user: dict) -> dict:
    attributes = user.get("attributes") or {}
    return _compact({
        "username": user.get("username"),
        **{field: attributes.get(name) for field, name in USER_FIELDS.items()},
        "disabled": _disabled(user),
        "password_expired": attributes.get("expired") == "true" or None,
        "last_active": _timestamp(user.get("lastActive")),
    })


def _record(record: dict) -> dict:
    return _compact({
        "username": record.get("username"),
        "connection": record.get("connectionName"),
        "remote_host": record.get("remoteHost"),
        "start": _timestamp(record.get("startDate")),
        "end": _timestamp(record.get("endDate")),
        "active": record.get("active") or None,
    })


def _latest(records: list | None, limit: int) -> list:
    return sorted(records or [], key=lambda r: r.get("startDate") or 0, reverse=True)[:max(limit, 0)]


def _count(permissions: dict | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for granted in (permissions or {}).values():
        for permission in granted:
            counts[permission] = counts.get(permission, 0) + 1
    return dict(sorted(counts.items()))


def _patch(path: str, add: list[str] | None, remove: list[str] | None) -> list[dict]:
    return [{"op": "add", "path": path, "value": v} for v in add or []] + [
        {"op": "remove", "path": path, "value": v} for v in remove or []
    ]


def _ambiguous_groups(query: str, groups: list[ConnectionGroup]) -> str:
    names = "\n".join(f"- {g.path} (id {g.identifier})" for g in groups[:30])
    return f"'{query}' matches several connection groups; use the exact path or identifier:\n{names}"
