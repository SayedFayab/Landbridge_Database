# Landbridge_Database.py
import os
import json
import hashlib
import hmac
import datetime as dt
from typing import Dict, List, Tuple, Any, Optional

import mysql.connector
from mysql.connector import Error, errorcode
import pandas as pd
import streamlit as st
from pathlib import Path
import textwrap  # for showing SQL if CREATE is not allowed

# ===================== FLAGS (flip these as you like) =====================
# If True, require an extra gate password before anything else.
REQUIRE_APP_GATE = False
# If True, auto-connect to DB from secrets/env; hide DB login unless secrets missing.
PREFER_DB_SECRETS = True

# ===================== LOGO (optional) =====================
def _app_dir() -> Path:
    try:
        return Path(__file__).resolve().parent
    except NameError:
        return Path.cwd()

APP_DIR = _app_dir()
for _cand in [
    APP_DIR / "assets" / "landbridge_logo.png",
    APP_DIR / "assets" / "logo.png",
    APP_DIR / "landbridge_logo.png",
    APP_DIR / "logo.png",
]:
    LOGO_PATH = _cand if _cand.exists() else None
    if LOGO_PATH:
        break
PAGE_ICON = str(LOGO_PATH) if LOGO_PATH else "🌉"

# ===================== PAGE =====================
st.set_page_config(page_title="Landbridge DB", page_icon=PAGE_ICON, layout="wide")
col_logo, col_title = st.columns([1, 8], vertical_alignment="center")
with col_logo:
    if LOGO_PATH:
        st.image(str(LOGO_PATH), use_container_width=True)
with col_title:
    st.title("Landbridge Innovation Centre Database")

# ===================== HELPERS =====================
def secret_or_env(key: str, default: Optional[str] = None) -> Optional[str]:
    try:
        return st.secrets[key]
    except Exception:
        return os.environ.get(key, default)

def get_conn(cfg: Dict[str, Any]):
    return mysql.connector.connect(
        host=cfg["host"],
        port=cfg.get("port", 3306),
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        connection_timeout=6,
    )

def cur(cnx):
    return cnx.cursor(dictionary=True, buffered=True)

def list_tables(cnx) -> List[str]:
    c = cur(cnx); c.execute("SHOW TABLES"); rows = c.fetchall(); c.close()
    names = [list(r.values())[0] for r in rows]
    return [t for t in names if t in ALLOWED_TABLES]

def cols(cnx, table) -> List[Dict[str, Any]]:
    q = """
    SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
    ORDER BY ORDINAL_POSITION
    """
    c = cur(cnx); c.execute(q, (table,)); out = c.fetchall(); c.close()
    return out

def pks(cnx, table) -> List[str]:
    q = """
    SELECT COLUMN_NAME
    FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME=%s AND CONSTRAINT_NAME='PRIMARY'
    ORDER BY ORDINAL_POSITION
    """
    c = cur(cnx); c.execute(q, (table,)); out = [r["COLUMN_NAME"] for r in c.fetchall()]; c.close()
    return out

def df_all(cnx, table) -> pd.DataFrame:
    c = cur(cnx); c.execute(f"SELECT * FROM `{table}`"); rows = c.fetchall(); c.close()
    return pd.DataFrame(rows)

# ===================== PASSWORDS (PBKDF2 + timing-safe compare) =====================
PBKDF2_ITERATIONS = 200_000

def hash_password(password: str) -> Tuple[bytes, int, bytes]:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt, PBKDF2_ITERATIONS, dk

def verify_password(password: str, salt, iterations: int, expected) -> bool:
    if isinstance(salt, (memoryview, bytearray)): salt = bytes(salt)
    if isinstance(expected, (memoryview, bytearray)): expected = bytes(expected)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    return hmac.compare_digest(dk, expected)

# ===================== SECURITY TABLES & AUDIT =====================
def ensure_security_tables(cnx):
    """Create internal tables if possible; otherwise show SQL to run once as root."""
    c = cur(cnx)
    c.execute("""
        SELECT TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME IN ('app_user','audit_log')
    """)
    existing = {r["TABLE_NAME"] for r in c.fetchall()}
    c.close()

    missing = {"app_user", "audit_log"} - existing
    if not missing:
        return

    try:
        c = cur(cnx)
        c.execute("""
            CREATE TABLE IF NOT EXISTS app_user (
              app_user_id INT AUTO_INCREMENT PRIMARY KEY,
              username VARCHAR(80) NOT NULL UNIQUE,
              pwd_hash VARBINARY(64) NOT NULL,
              pwd_salt VARBINARY(32) NOT NULL,
              iterations INT NOT NULL,
              role ENUM('admin','editor','viewer') NOT NULL DEFAULT 'viewer',
              is_active TINYINT(1) NOT NULL DEFAULT 1,
              created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              last_login_at DATETIME NULL
            ) ENGINE=InnoDB
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
              audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
              occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              app_user_id INT NULL,
              username VARCHAR(80) NULL,
              role ENUM('admin','editor','viewer') NULL,
              op ENUM('INSERT','UPDATE','DELETE') NOT NULL,
              table_name VARCHAR(128) NOT NULL,
              success TINYINT(1) NOT NULL,
              error_text TEXT NULL,
              sql_text TEXT NULL,
              params_json JSON NULL,
              CONSTRAINT fk_audit_user FOREIGN KEY (app_user_id) REFERENCES app_user(app_user_id)
                ON UPDATE CASCADE ON DELETE SET NULL
            ) ENGINE=InnoDB
        """)
        cnx.commit(); c.close()
    except Exception:
        st.error(
            "This DB user cannot CREATE the internal tables "
            f"({', '.join(sorted(missing))}). Run the SQL below once as an admin, then restart the app."
        )
        st.code(textwrap.dedent("""
        USE landbridge;
        CREATE TABLE IF NOT EXISTS app_user (
          app_user_id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(80) NOT NULL UNIQUE,
          pwd_hash VARBINARY(64) NOT NULL,
          pwd_salt VARBINARY(32) NOT NULL,
          iterations INT NOT NULL,
          role ENUM('admin','editor','viewer') NOT NULL DEFAULT 'viewer',
          is_active TINYINT(1) NOT NULL DEFAULT 1,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          last_login_at DATETIME NULL
        ) ENGINE=InnoDB;

        CREATE TABLE IF NOT EXISTS audit_log (
          audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
          occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          app_user_id INT NULL,
          username VARCHAR(80) NULL,
          role ENUM('admin','editor','viewer') NULL,
          op ENUM('INSERT','UPDATE','DELETE') NOT NULL,
          table_name VARCHAR(128) NOT NULL,
          success TINYINT(1) NOT NULL,
          error_text TEXT NULL,
          sql_text TEXT NULL,
          params_json JSON NULL,
          CONSTRAINT fk_audit_user FOREIGN KEY (app_user_id) REFERENCES app_user(app_user_id)
            ON UPDATE CASCADE ON DELETE SET NULL
        ) ENGINE=InnoDB;
        """), language="sql")
        st.stop()

def app_users_count(cnx) -> int:
    c = cur(cnx); c.execute("SELECT COUNT(*) AS n FROM app_user WHERE is_active=1"); n = c.fetchone()["n"]; c.close()
    return int(n)

def create_app_user(cnx, username: str, password: str, role: str) -> None:
    salt, iters, dk = hash_password(password)
    c = cur(cnx)
    c.execute(
        "INSERT INTO app_user (username, pwd_hash, pwd_salt, iterations, role) VALUES (%s,%s,%s,%s,%s)",
        (username, dk, salt, iters, role),
    ); cnx.commit(); c.close()

def get_user_by_username(cnx, username: str) -> Optional[Dict[str, Any]]:
    c = cur(cnx); c.execute("SELECT * FROM app_user WHERE username=%s AND is_active=1", (username,))
    user = c.fetchone(); c.close(); return user

def update_last_login(cnx, app_user_id: int) -> None:
    c = cur(cnx); c.execute("UPDATE app_user SET last_login_at=%s WHERE app_user_id=%s", (dt.datetime.now(), app_user_id))
    cnx.commit(); c.close()

def log_audit(cnx, app_user: Optional[Dict[str, Any]], op: str, table: str,
              success: bool, error_text: Optional[str], sql_text: str, params: Tuple[Any, ...]) -> None:
    c = cur(cnx)
    try: payload = json.dumps(params, default=str)
    except Exception: payload = json.dumps([str(p) for p in params])
    uid = app_user["app_user_id"] if app_user else None
    uname = app_user["username"] if app_user else None
    role = app_user["role"] if app_user else None
    c.execute("""
        INSERT INTO audit_log (app_user_id, username, role, op, table_name, success, error_text, sql_text, params_json)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (uid, uname, role, op, table, 1 if success else 0, error_text, sql_text, payload))
    cnx.commit(); c.close()

# ===================== FKs & WIDGETS =====================
def foreign_keys(cnx, table) -> Dict[str, Tuple[str, str]]:
    q = """
    SELECT COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
    FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME=%s
      AND REFERENCED_TABLE_NAME IS NOT NULL
    """
    c = cur(cnx); c.execute(q, (table,)); out = {r["COLUMN_NAME"]: (r["REFERENCED_TABLE_NAME"], r["REFERENCED_COLUMN_NAME"]) for r in c.fetchall()}; c.close()
    return out

def _fk_label_columns(cnx, ref_table, ref_col):
    names = [x["COLUMN_NAME"] for x in cols(cnx, ref_table)]
    if {"first_name", "last_name"}.issubset(names): return ["first_name", "last_name"]
    for cand in ["name", "title", "email"]:
        if cand in names: return [cand]
    return [ref_col]

def fk_options(cnx, ref_table, ref_col, limit=500):
    label_cols = _fk_label_columns(cnx, ref_table, ref_col)
    sel_cols = [ref_col] + label_cols
    sel_list = ", ".join(f"`{c}`" for c in sel_cols)
    order_by = f"`{label_cols[0]}`"
    q = f"SELECT {sel_list} FROM `{ref_table}` ORDER BY {order_by} LIMIT %s"
    c = cur(cnx); c.execute(q, (limit,)); rows = c.fetchall(); c.close()
    opts = []
    for r in rows:
        parts = [str(r.get(cn, "")) for cn in label_cols]
        label = " ".join(p for p in parts if p).strip() or str(r[ref_col])
        opts.append((r[ref_col], label))
    return opts

def fk_selectbox(cnx, table, colname, ref_table, ref_col, nullable: bool, preselected=None):
    opts = fk_options(cnx, ref_table, ref_col)
    if not opts:
        st.warning(f"No rows found in `{ref_table}` for `{table}.{colname}`. Create one first.")
        return None
    id_list = [o[0] for o in opts]; labels = {o[0]: o[1] for o in opts}
    if nullable: id_list = [None] + id_list
    def fmt(v): return "— select —" if v is None else f"{v} — {labels.get(v, v)}"
    index = id_list.index(preselected) if preselected in id_list else 0
    return st.selectbox(
        f"{colname} (FK → {ref_table}.{ref_col})",
        id_list,
        index=index,
        format_func=fmt,
        key=f"fk_{table}_{colname}"
    )

def widget(colname: str, datatype: str, default_val=None):
    dv = default_val
    if isinstance(dv, bytes): dv = dv.decode("utf-8", errors="ignore")
    if datatype in ("int","bigint","smallint","mediumint","tinyint"):
        try: dv = int(dv) if dv is not None else 0
        except: dv = 0
        return st.number_input(f"{colname} (int)", value=dv, step=1, key=f"ni_{colname}")
    if datatype in ("decimal","float","double"):
        try: dv = float(dv) if dv is not None else 0.0
        except: dv = 0.0
        return st.number_input(f"{colname} (num)", value=dv, key=f"nf_{colname}")
    if datatype == "date": return st.text_input(f"{colname} (YYYY-MM-DD)", value=dv or "", key=f"ti_{colname}")
    if datatype in ("datetime","timestamp"): return st.text_input(f"{colname} (YYYY-MM-DD HH:MM:SS)", value=dv or "", key=f"td_{colname}")
    return st.text_input(colname, value=str(dv) if dv is not None else "", key=f"tx_{colname}")

def _is_auto_ts(col_default) -> bool:
    if col_default is None: return False
    d = str(col_default).strip().lower()
    return ("current_timestamp" in d) or (d in {"now()", "curdate()", "current_date"})

def role_allows(op: str, role: str) -> bool:
    if role == "viewer": return (op == "READ")
    return True

# ===================== CRUD UIs =====================
def insert_ui(cnx, table, columns, app_user):
    if not role_allows("INSERT", app_user["role"]):
        st.error("Your role does not permit creating records."); return None, None
    fks = foreign_keys(cnx, table)
    insertable = [c for c in columns if "auto_increment" not in (c["EXTRA"] or "") and not _is_auto_ts(c["COLUMN_DEFAULT"])]
    inputs = {}
    for cdef in insertable:
        name = cdef["COLUMN_NAME"]; dtype = cdef["DATA_TYPE"]; nullable = (cdef["IS_NULLABLE"] == "YES")
        if name in fks:
            ref_table, ref_col = fks[name]
            inputs[name] = fk_selectbox(cnx, table, name, ref_table, ref_col, nullable)
        else:
            inputs[name] = widget(name, dtype, cdef["COLUMN_DEFAULT"])
    if st.button("Create", key=f"create_btn_{table}"):
        col_parts, val_parts, params = [], [], []
        for cdef in insertable:
            name = cdef["COLUMN_NAME"]; v = inputs[name]
            if isinstance(v, str) and v.strip() == "": v = None
            if v is None and cdef["IS_NULLABLE"] != "YES": st.error(f"Column `{name}` is required."); return None, None
            col_parts.append(f"`{name}`"); val_parts.append("%s"); params.append(v)
        if not col_parts: st.warning("Nothing to insert."); return None, None
        sql = f"INSERT INTO `{table}` ({', '.join(col_parts)}) VALUES ({', '.join(val_parts)})"
        return sql, tuple(params)
    return None, None

def update_ui(cnx, table, columns, primary_keys, app_user):
    if not role_allows("UPDATE", app_user["role"]):
        st.error("Your role does not permit updating records."); return None, None
    if not primary_keys or len(primary_keys) > 1: st.info("Update requires a single-column primary key."); return None, None
    pk = primary_keys[0]; df = df_all(cnx, table)
    if df.empty: st.info("No rows to update."); return None, None
    selected = st.selectbox(f"Select {pk} to edit", df[pk].tolist(), key=f"upd_select_{table}_{pk}")
    c = cur(cnx); c.execute(f"SELECT * FROM `{table}` WHERE `{pk}`=%s", (selected,)); row = c.fetchone(); c.close()
    st.caption("Current row:"); st.dataframe(pd.DataFrame([row]), use_container_width=True)
    fks = foreign_keys(cnx, table)
    set_cols = [col for col in columns if col["COLUMN_NAME"] not in primary_keys and not _is_auto_ts(col["COLUMN_DEFAULT"])]
    inputs = {}
    for cdef in set_cols:
        name = cdef["COLUMN_NAME"]; dtype = cdef["DATA_TYPE"]; nullable = (cdef["IS_NULLABLE"] == "YES"); current = row.get(name)
        if name in fks:
            ref_table, ref_col = fks[name]
            inputs[name] = fk_selectbox(cnx, table, name, ref_table, ref_col, nullable, preselected=current)
        else:
            inputs[name] = widget(name, dtype, current)
    if st.button("Update", key=f"update_btn_{table}"):
        set_clause = ", ".join(f"`{c['COLUMN_NAME']}`=%s" for c in set_cols)
        sql = f"UPDATE `{table}` SET {set_clause} WHERE `{pk}`=%s"
        params = []
        for cdef in set_cols:
            v = inputs[cdef["COLUMN_NAME"]]
            if isinstance(v, str) and v.strip() == "": v = None
            if v is None and cdef["IS_NULLABLE"] != "YES": st.error(f"Column `{cdef['COLUMN_NAME']}` is required."); return None, None
            params.append(v)
        params.append(selected)
        return sql, tuple(params)
    return None, None

def delete_ui(cnx, table, primary_keys, app_user):
    if not role_allows("DELETE", app_user["role"]):
        st.error("Your role does not permit deleting records."); return None, None
    if not primary_keys or len(primary_keys) > 1: st.info("Delete requires a single-column primary key."); return None, None
    pk = primary_keys[0]; df = df_all(cnx, table)
    if df.empty: st.info("No rows to delete."); return None, None
    selected = st.selectbox(f"Select {pk} to delete", df[pk].tolist(), key=f"del_select_{table}_{pk}")
    if st.button("Delete", type="primary", key=f"delete_btn_{table}"):
        return f"DELETE FROM `{table}` WHERE `{pk}`=%s", (selected,)
    return None, None

def exec_write(cnx, sql: str, params: Tuple[Any, ...], op: str, table: str, app_user: Dict[str, Any]) -> Optional[Exception]:
    if not role_allows(op, app_user["role"]):
        return Exception(f"Role '{app_user['role']}' not permitted for {op}.")
    c = cur(cnx); err = None
    try:
        c.execute(sql, params); cnx.commit(); st.toast(f"{op} on `{table}` successful", icon="✅")
    except Exception as e:
        cnx.rollback(); err = e
    finally:
        c.close()
        try: log_audit(cnx, app_user, op, table, err is None, None if err is None else str(err), sql, params)
        except Exception: pass
    return err

# ===================== USER MANAGEMENT (ADMIN) =====================
def user_mgmt_ui(cnx, current_user):
    if current_user.get("role") != "admin":
        st.info("Only admins can manage users.")
        return

    def _count_active_admins():
        c = cur(cnx); c.execute("SELECT COUNT(*) AS n FROM app_user WHERE is_active=1 AND role='admin'")
        n = int(c.fetchone()["n"]); c.close(); return n

    def _list_users():
        c = cur(cnx)
        c.execute("""SELECT app_user_id, username, role, is_active, created_at, last_login_at
                     FROM app_user ORDER BY username""")
        rows = c.fetchall(); c.close(); return rows

    st.subheader("👤 User management (admin)")
    tabs = st.tabs(["➕ Create user", "🔑 Reset password", "🛠 Manage users", "🗑️ Delete user", "📋 All users"])

    # Create user
    with tabs[0]:
        with st.form("create_user_form", clear_on_submit=True):
            new_username = st.text_input("Username", key="um_create_username")
            new_role = st.selectbox("Role", ["viewer", "editor", "admin"], index=2, key="um_create_role")
            pw1 = st.text_input("Password", type="password", key="um_create_pw1")
            pw2 = st.text_input("Confirm password", type="password", key="um_create_pw2")
            submitted = st.form_submit_button("Create user")
        if submitted:
            if not new_username or not pw1:
                st.error("Username and password are required.")
            elif pw1 != pw2:
                st.error("Passwords do not match.")
            else:
                try:
                    create_app_user(cnx, new_username, pw1, role=new_role)
                    log_audit(cnx, current_user, "INSERT", "app_user", True, None, "CREATE USER", (new_username, new_role))
                    st.success(f"User **{new_username}** created.")
                except Exception as e:
                    log_audit(cnx, current_user, "INSERT", "app_user", False, str(e), "CREATE USER", (new_username, new_role))
                    st.error(f"Failed to create user: {e}")

    # Reset password
    with tabs[1]:
        users = _list_users()
        if not users:
            st.info("No users yet.")
        else:
            uname_list = [u["username"] for u in users]
            sel_uname = st.selectbox("Select user", uname_list, index=0, key="um_reset_select_user")
            with st.form("reset_pw_form"):
                npw1 = st.text_input("New password", type="password", key="um_reset_pw1")
                npw2 = st.text_input("Confirm new password", type="password", key="um_reset_pw2")
                do_reset = st.form_submit_button("Reset password")
            if do_reset:
                if npw1 != npw2:
                    st.error("Passwords do not match.")
                else:
                    try:
                        salt, iters, dk = hash_password(npw1)
                        c = cur(cnx)
                        c.execute("""UPDATE app_user
                                     SET pwd_hash=%s, pwd_salt=%s, iterations=%s
                                     WHERE username=%s""",
                                  (dk, salt, PBKDF2_ITERATIONS, sel_uname))
                        cnx.commit(); c.close()
                        log_audit(cnx, current_user, "UPDATE", "app_user", True, None, "RESET PASSWORD", (sel_uname,))
                        st.success(f"Password reset for **{sel_uname}**.")
                    except Exception as e:
                        cnx.rollback()
                        log_audit(cnx, current_user, "UPDATE", "app_user", False, str(e), "RESET PASSWORD", (sel_uname,))
                        st.error(f"Failed to reset password: {e}")

    # Manage role / active
    with tabs[2]:
        users = _list_users()
        if not users:
            st.info("No users yet.")
        else:
            uname_list = [u["username"] for u in users]
            sel_uname = st.selectbox("Select user", uname_list, index=0, key="um_manage_select_user")
            sel = next(u for u in users if u["username"] == sel_uname)

            new_role = st.selectbox("Role", ["viewer", "editor", "admin"],
                                    index=["viewer","editor","admin"].index(sel["role"]),
                                    key="um_manage_role")
            new_active = st.checkbox("Active", value=bool(sel["is_active"]), key="um_manage_active")
            cannot_deactivate_self = (sel_uname == current_user["username"])

            last_admin_block = False
            if sel["role"] == "admin" and (not new_active or new_role != "admin"):
                active_admins = _count_active_admins()
                if active_admins <= 1:
                    last_admin_block = True

            if cannot_deactivate_self and not new_active:
                st.warning("You cannot deactivate your own account.")
            if last_admin_block:
                st.warning("You cannot remove the last active admin.")

            if st.button("Save changes", key="um_manage_save"):
                if cannot_deactivate_self and not new_active:
                    st.error("Blocked: cannot deactivate your own account.")
                elif last_admin_block:
                    st.error("Blocked: this would leave zero active admins.")
                else:
                    try:
                        c = cur(cnx)
                        c.execute("""UPDATE app_user SET role=%s, is_active=%s WHERE username=%s""",
                                  (new_role, 1 if new_active else 0, sel_uname))
                        cnx.commit(); c.close()
                        log_audit(cnx, current_user, "UPDATE", "app_user", True, None, "UPDATE USER", (sel_uname, new_role, new_active))
                        st.success("User updated.")
                    except Exception as e:
                        cnx.rollback()
                        log_audit(cnx, current_user, "UPDATE", "app_user", False, str(e), "UPDATE USER", (sel_uname, new_role, new_active))
                        st.error(f"Failed to update user: {e}")

    # Delete user (with safeguards)
    with tabs[3]:
        users = _list_users()
        if not users:
            st.info("No users yet.")
        else:
            uname_list = [u["username"] for u in users]
            del_uname = st.selectbox("Select user to delete", uname_list, index=0, key="um_delete_select_user")
            del_row = next(u for u in users if u["username"] == del_uname)
            cannot_delete_self = (del_uname == current_user["username"])

            # Would this remove the last active admin?
            last_admin_block = False
            if del_row["role"] == "admin" and del_row["is_active"]:
                active_admins = _count_active_admins()
                if active_admins <= 1:
                    last_admin_block = True

            st.warning("Deleting a user cannot be undone. Audit logs keep historical actions; the FK sets app_user_id to NULL.")
            confirm_text = st.text_input("Type the username to confirm deletion", key="um_delete_confirm_text")
            if cannot_delete_self:
                st.info("You cannot delete your own account.")
            if last_admin_block:
                st.info("You cannot delete the last active admin.")

            if st.button("Delete user", type="primary", key="um_delete_btn"):
                if cannot_delete_self:
                    st.error("Blocked: cannot delete your own account.")
                elif last_admin_block:
                    st.error("Blocked: this would remove the last active admin.")
                elif confirm_text.strip() != del_uname:
                    st.error("Confirmation text does not match the selected username.")
                else:
                    try:
                        c = cur(cnx)
                        c.execute("DELETE FROM app_user WHERE username=%s", (del_uname,))
                        cnx.commit(); c.close()
                        log_audit(cnx, current_user, "DELETE", "app_user", True, None, "DELETE USER", (del_uname,))
                        st.success(f"User **{del_uname}** deleted.")
                    except Exception as e:
                        cnx.rollback()
                        log_audit(cnx, current_user, "DELETE", "app_user", False, str(e), "DELETE USER", (del_uname,))
                        st.error(f"Failed to delete user: {e}")

    # View users
    with tabs[4]:
        df = pd.DataFrame(_list_users())
        st.dataframe(df, use_container_width=True)

# ===================== TABLE WHITELIST =====================
ALLOWED_TABLES = [
    "organization", "person", "program", "project", "fund",
    "donation", "receipt_sequence", "grant_award", "vendor",
    "expense", "event", "volunteer_shift",
]

# ===================== (OPTIONAL) APP GATE =====================
if REQUIRE_APP_GATE:
    with st.sidebar:
        if LOGO_PATH: st.image(str(LOGO_PATH), use_container_width=True)
        st.header("🔐 App Access")
        expected_pwd = secret_or_env("APP_ADMIN_PASSWORD", None)
        app_pwd = st.text_input("App password", type="password", key="gate_pw")
        login_clicked = st.button("Enter", type="primary", key="gate_btn")
    if not expected_pwd:
        st.error("Set APP_ADMIN_PASSWORD (env or secrets) or disable REQUIRE_APP_GATE.")
        st.stop()
    if "admin_ok" not in st.session_state: st.session_state.admin_ok = False
    if login_clicked: st.session_state.admin_ok = (app_pwd == expected_pwd)
    if not st.session_state.admin_ok:
        st.info("Enter the **app password** in the sidebar to continue."); st.stop()

# ===================== DB CONNECTION =====================
def cfg_from_secrets() -> Optional[Dict[str, Any]]:
    host = secret_or_env("MYSQL_HOST"); port = secret_or_env("MYSQL_PORT")
    user = secret_or_env("MYSQL_USER"); pwd = secret_or_env("MYSQL_PASSWORD")
    db = secret_or_env("MYSQL_DB")
    if not (host and user and pwd and db): return None
    try: port = int(port) if port else 3306
    except: port = 3306
    return {"host": host, "port": port, "user": user, "password": pwd, "database": db}

db_cfg = None
if PREFER_DB_SECRETS:
    db_cfg = cfg_from_secrets()

with st.sidebar:
    st.header("🗄️ Database")
    if LOGO_PATH: st.image(str(LOGO_PATH), use_container_width=True)
    if db_cfg:
        st.success(f"Using DB from secrets: {db_cfg['host']}:{db_cfg['port']} / {db_cfg['database']}")
    else:
        st.info("No DB secrets found — enter credentials below.")
        host = st.text_input("Host", value="localhost", key="db_host")
        port = st.number_input("Port", min_value=1, max_value=65535, value=3306, step=1, key="db_port")
        user = st.text_input("DB User", value="root", key="db_user")
        password = st.text_input("DB Password", type="password", value="", key="db_pass")
        database = st.text_input("Database", value="landbridge", key="db_name")
        if st.button("Connect", key="db_connect"):
            if not host or not user or not database:
                st.error("Please fill Host, DB User, and Database.")
            else:
                db_cfg = {"host": host, "port": int(port), "user": user, "password": password, "database": database}

if not db_cfg:
    st.stop()

try:
    cnx = get_conn(db_cfg)
    st.success(f"Connected to **{db_cfg['database']}** at **{db_cfg['host']}:{db_cfg['port']}** as **{db_cfg['user']}** ✅")
except Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        st.error(f"Access denied. MySQL says: {err.msg}")
        st.caption(
            f"Connecting as user={db_cfg.get('user')} host={db_cfg.get('host')} "
            f"port={db_cfg.get('port')} db={db_cfg.get('database')}"
        )
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        st.error(f"Unknown database `{db_cfg['database']}`.")
    else:
        st.error(f"MySQL Error {err.errno}: {err}")
    st.stop()
except Exception as e:
    st.error(f"Unexpected error: {e!r}")
    st.stop()

# Ensure security tables exist (handles low-priv users gracefully)
ensure_security_tables(cnx)

# ===================== FIRST ADMIN OR LOGIN =====================
if app_users_count(cnx) == 0:
    st.warning("No application users exist. Create the initial **admin** account.")
    with st.form("first_admin"):
        new_user = st.text_input("Admin username", value="admin", key="first_admin_user")
        pw1 = st.text_input("Admin password", type="password", key="first_admin_pw1")
        pw2 = st.text_input("Confirm password", type="password", key="first_admin_pw2")
        submitted = st.form_submit_button("Create admin", type="primary")
    if submitted:
        if not new_user or not pw1:
            st.error("Username and password are required.")
        elif pw1 != pw2:
            st.error("Passwords do not match.")
        else:
            try:
                create_app_user(cnx, new_user, pw1, role="admin")
                st.success("Admin user created. Please log in below.")
            except Exception as e:
                st.error(f"Failed to create admin: {e}")

if "app_user" not in st.session_state or not st.session_state.get("app_user"):
    st.subheader("Sign in")
    with st.form("app_login"):
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pass")
        submitted = st.form_submit_button("Login", type="primary")
    if submitted:
        user_row = get_user_by_username(cnx, u)
        if not user_row:
            st.error("Invalid username or inactive account.")
        else:
            if verify_password(p, user_row["pwd_salt"], int(user_row["iterations"]), user_row["pwd_hash"]):
                st.session_state.app_user = {
                    "app_user_id": user_row["app_user_id"],
                    "username": user_row["username"],
                    "role": user_row["role"],
                }
                update_last_login(cnx, user_row["app_user_id"])
                st.rerun()
            else:
                st.error("Incorrect password.")
    st.stop()

with st.sidebar:
    st.markdown("---")
    au = st.session_state.app_user
    st.write(f"**User:** {au['username']} ({au['role']})")
    if st.button("Logout", key="logout_btn"): st.session_state.app_user = None; st.rerun()

# Admin-only user management UI
if st.session_state.app_user["role"] == "admin":
    with st.expander("👤 User management (admin)", expanded=False):
        user_mgmt_ui(cnx, st.session_state.app_user)

# ===================== QUICK HELPERS =====================
def seed_basic_funds(cnx):
    samples = [("General (Unrestricted)", 0, "Default unrestricted fund"),
               ("Youth Program (Restricted)", 1, "Restricted to youth initiatives")]
    c = cur(cnx); created = 0
    for name, restricted, notes in samples:
        c.execute("SELECT fund_id FROM fund WHERE name=%s", (name,))
        if not c.fetchone():
            c.execute("INSERT INTO fund (name, restricted, notes) VALUES (%s,%s,%s)", (name, restricted, notes))
            created += 1
    cnx.commit(); c.close(); return created

with st.expander("🔧 Quick setup helpers", expanded=False):
    if "fund" in list_tables(cnx):
        if st.button("Seed sample funds", key="seed_funds_btn"):
            try: n = seed_basic_funds(cnx); st.success(f"Inserted {n} fund(s).")
            except Exception as e: st.error(f"Seeding failed: {e}")

# ===================== MAIN =====================
tables = list_tables(cnx)
if not tables:
    st.warning("No whitelisted tables found in this database.")
    try: cnx.close()
    except: pass
    st.stop()

sel_table = st.selectbox("Choose a table", options=tables, index=0, key="choose_table")

ops = ["Read"]
if st.session_state.app_user["role"] in ("editor","admin"):
    ops = ["Read","Create","Update","Delete"]
operation = st.radio("Operation", ops, horizontal=True, key="op_radio")

table_cols = cols(cnx, sel_table); table_pks = pks(cnx, sel_table)
with st.expander("Table schema"):
    st.dataframe(pd.DataFrame(table_cols), use_container_width=True)

if sel_table == "donation" and operation == "Create" and "receipt_sequence" in tables:
    st.caption("For official receipts, ensure donor info is in `person`. Leave timestamp fields blank (auto).")
    if st.button("Suggest Receipt Number", key="suggest_receipt_btn"):
        try:
            year = dt.date.today().year
            c = cur(cnx); c.execute("SELECT last_seq FROM receipt_sequence WHERE seq_year=%s", (year,))
            row = c.fetchone(); last = 0 if row is None else row["last_seq"]; new_seq = int(last) + 1
            if row is None: c.execute("INSERT INTO receipt_sequence (seq_year, last_seq) VALUES (%s,%s)", (year, 0))
            c.execute("UPDATE receipt_sequence SET last_seq=%s WHERE seq_year=%s", (new_seq, year))
            cnx.commit(); c.close(); st.success(f"Suggested: LB-{year}-{new_seq:06d}")
        except Exception as e:
            st.error(f"Could not generate: {e}")

if operation == "Read":
    st.subheader(f"Read — `{sel_table}`")
    df = df_all(cnx, sel_table); st.dataframe(df if not df.empty else pd.DataFrame(), use_container_width=True)

elif operation == "Create":
    st.subheader(f"Create — `{sel_table}`")
    sql, params = insert_ui(cnx, sel_table, table_cols, st.session_state.app_user)
    if sql:
        err = exec_write(cnx, sql, params, "INSERT", sel_table, st.session_state.app_user)
        if err: st.error(f"Insert failed: {err}")
        else: st.dataframe(df_all(cnx, sel_table), use_container_width=True)

elif operation == "Update":
    st.subheader(f"Update — `{sel_table}`")
    sql, params = update_ui(cnx, sel_table, table_cols, table_pks, st.session_state.app_user)
    if sql:
        err = exec_write(cnx, sql, params, "UPDATE", sel_table, st.session_state.app_user)
        if err: st.error(f"Update failed: {err}")
        else: st.dataframe(df_all(cnx, sel_table), use_container_width=True)

elif operation == "Delete":
    st.subheader(f"Delete — `{sel_table}`")
    sql, params = delete_ui(cnx, sel_table, table_pks, st.session_state.app_user)
    if sql:
        err = exec_write(cnx, sql, params, "DELETE", sel_table, st.session_state.app_user)
        if err: st.error(f"Delete failed: {err}")
        else: st.dataframe(df_all(cnx, sel_table), use_container_width=True)

try: cnx.close()
except: pass
