"""Command-line administration for FindBack.

  python manage.py migrate                 # create / upgrade the database (backs up legacy DBs first)
  python manage.py create-admin            # create the first administrator (prompts securely)
  python manage.py create-student          # add a student from the terminal (admins can use the web UI)
  python manage.py list-users              # show accounts (never shows passwords)
"""
import argparse
import getpass
import sys

import models
from config import Config
from validators import ValidationError


def cmd_migrate(args):
    before = models.get_schema_version(Config.DATABASE)
    models.init_db(Config.DATABASE)
    after = models.get_schema_version(Config.DATABASE)
    print(f"Database: {Config.DATABASE}\nSchema version: {before} -> {after}")


def cmd_create_admin(args):
    models.init_db(Config.DATABASE)
    username = args.username or input("Admin username: ").strip()
    name = args.name or input("Full name: ").strip()
    password = getpass.getpass("Password (min 8 chars, letter + digit): ")
    if password != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return 1
    try:
        uid = models.create_staff(username, name, models.ROLE_ADMIN, password, created_by=None,
                                  min_length=Config.PASSWORD_MIN_LENGTH)
    except ValidationError as exc:
        print("Could not create admin:\n  - " + "\n  - ".join(exc.errors))
        return 1
    print(f"Administrator '{username.lower()}' created (id {uid}). Sign in on the 'Admin / Teacher' tab.")
    return 0


def cmd_create_student(args):
    models.init_db(Config.DATABASE)
    try:
        sid = models.create_student(args.roll, args.name, args.mobile, args.branch or "", args.year or "",
                                    created_by=None, roll_regex=Config.ROLL_NUMBER_REGEX,
                                    mobile_regex=Config.MOBILE_REGEX)
    except ValidationError as exc:
        print("Could not create student:\n  - " + "\n  - ".join(exc.errors))
        return 1
    print(f"Student created (id {sid}). Initial password = registered mobile; change forced at first login.")
    return 0


def cmd_list_users(args):
    conn = models.get_db(Config.DATABASE)
    try:
        for r in conn.execute("SELECT id, role, roll_number, username, name, is_active, is_deleted, "
                              "must_change_password FROM users ORDER BY role, id"):
            flags = ("active" if r["is_active"] else "inactive") + (", deleted" if r["is_deleted"] else "") \
                + (", pw-change-pending" if r["must_change_password"] else "")
            print(f"#{r['id']:<4} {models.ROLE_LABELS.get(r['role'], r['role']):<14} "
                  f"{(r['roll_number'] or r['username'] or '-'):<14} {r['name']:<28} [{flags}]")
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    p = sub.add_parser("create-admin")
    p.add_argument("--username")
    p.add_argument("--name")
    p.set_defaults(fn=cmd_create_admin)
    p = sub.add_parser("create-student")
    p.add_argument("--roll", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--mobile", required=True)
    p.add_argument("--branch")
    p.add_argument("--year")
    p.set_defaults(fn=cmd_create_student)
    sub.add_parser("list-users").set_defaults(fn=cmd_list_users)
    args = parser.parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
