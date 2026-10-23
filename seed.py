import os
import json
import secrets
import string
from datetime import datetime, timedelta, timezone
from config import Config
import models
from models import init_db, create_student, create_staff, create_report, create_claim, get_db


def _random_password():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(14)) + "a1"


def seed_database(db_path=None):
    """Demo data for local testing. Students get roll numbers with their mobile as the initial
    password (forced change at first login). The demo admin password comes from the
    SEED_ADMIN_PASSWORD environment variable, or is generated and printed ONCE."""
    if db_path is None:
        db_path = Config.DATABASE

    print(f"[*] Initializing database at {db_path}...")
    init_db(db_path)

    conn = get_db(db_path)
    n = conn.execute("SELECT COUNT(*) FROM users WHERE role='user' AND roll_number IS NOT NULL").fetchone()[0]
    conn.close()
    if n > 0:
        print("[!] Students already exist. Skipping duplicate seeding.")
        return

    admin_pw = os.getenv("SEED_ADMIN_PASSWORD") or _random_password()
    generated = not os.getenv("SEED_ADMIN_PASSWORD")
    conn = get_db(db_path)
    has_admin = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] > 0
    conn.close()
    admin_id = None
    if not has_admin:
        admin_id = create_staff("admin", "Chief Campus Security", models.ROLE_ADMIN, admin_pw, db_path=db_path)

    arun = create_student("21CS001", "Arun Kumar", "9876500001", "B.Tech CSE", "2nd Year", admin_id, db_path)
    sarah = create_student("21CS002", "Sarah Jenkins", "9876500002", "B.Tech CSE", "2nd Year", admin_id, db_path)
    marcus = create_student("21EC003", "Marcus Vance", "9876500003", "B.Tech ECE", "3rd Year", admin_id, db_path)

    today = datetime.now(timezone.utc)
    d_yesterday = (today - timedelta(days=1)).strftime('%Y-%m-%d')
    d_2days = (today - timedelta(days=2)).strftime('%Y-%m-%d')
    d_3days = (today - timedelta(days=3)).strftime('%Y-%m-%d')
    d_today = today.strftime('%Y-%m-%d')

    create_report(user_id=sarah, report_type='lost', item_name='Dell XPS 15 9520 Laptop', category='Electronics',
        description='Silver Dell laptop with matte finish. Has programming stickers on the lid and small scratch on the right USB-C port.',
        date_occurred=d_2days, location='Main University Library 2nd Floor Silent Study Area',
        distinguishing_features='Linux Tux penguin sticker on lower left palmrest, serial service tag ends with 8X99',
        private_contact='9876500002', db_path=db_path)
    found_1 = create_report(user_id=arun, report_type='found', item_name='Silver Dell Laptop with Stickers',
        category='Electronics', description='Found a silver Dell laptop left on table 14 near the windows with power adapter.',
        date_occurred=d_yesterday, location='Main Library 2nd Floor near East Wing',
        distinguishing_features='Sticker on palmrest has Linux penguin decal; Dell service tag ends in 8X99',
        private_contact='Security Desk Dropoff', db_path=db_path)
    create_report(user_id=arun, report_type='lost', item_name='Brown Leather Bi-Fold Wallet', category='Wallets & Bags',
        description='Dark brown leather wallet with embossed stitching. Contained campus transit card and gym membership card.',
        date_occurred=d_yesterday, location='Student Cafeteria / Food Court near Subway',
        distinguishing_features='Contains student bus pass ending in 4092, small folded emergency $20 bill behind driver license',
        private_contact='9876500001', db_path=db_path)
    create_report(user_id=marcus, report_type='found', item_name='Brown Leather Wallet with Cards',
        category='Wallets & Bags', description='Handed over to security desk: brown leather bi-fold wallet found under cafeteria booth.',
        date_occurred=d_yesterday, location='Dining Commons Cafeteria Booth Area',
        distinguishing_features='Transit pass inside with student ID # ending 4092, bill folded in inner slot',
        private_contact='Campus Security Safe Box #12', db_path=db_path)
    create_report(user_id=marcus, report_type='found', item_name='AirPods Pro 2 in Matte Black Case', category='Electronics',
        description='Apple AirPods wireless charging case found on treadmill console.', date_occurred=d_today,
        location='Campus Recreation Gym Cardio Zone', distinguishing_features='Engraved emoji with initials "MV" on front of matte case',
        private_contact='Gym Reception Desk', db_path=db_path)
    create_report(user_id=sarah, report_type='lost', item_name='Blue Campus Lanyard with RFID Keyfob', category='Keys',
        description='Navy blue woven neck lanyard with two brass cylinder keys and round gray RFID entrance badge.',
        date_occurred=d_3days, location='Robotics Innovation Lab Courtyard Walkway',
        distinguishing_features='Has miniature silver screwdriver keychain charm attached', private_contact='9876500002', db_path=db_path)

    claim_answers = json.dumps({
        "distinguishing_proof": "The laptop has a round black-and-white Linux Tux sticker on the palmrest to the left of the touchpad, and the Dell service tag ends in 8X99.",
        "contents_or_pouch_details": "It was kept with a black 65W USB-C Dell charger with a blue velcro cable tie.",
        "marks_or_serial_number": "Dell Service Tag: DL-8X992A-X",
        "loss_circumstances": "Left on table 14 while rushing to afternoon Database Systems lecture at 2:15 PM."}, indent=2)
    claim_id = create_claim(found_1, sarah, claim_answers, "9876500002", db_path=db_path)

    print("[OK] Seeding completed.")
    if admin_id:
        print("    Admin sign-in (Admin / Teacher tab): username 'admin'")
        if generated:
            print(f"    One-time generated admin password: {admin_pw}   <-- copy it now; it is not stored anywhere")
    print("    Demo students (Student tab): roll 21CS001 / 21CS002 / 21EC003; initial password = registered mobile")
    print("    (9876500001 / 9876500002 / 9876500003). A password change is forced at first login.")
    print(f"    Pending claim #{claim_id} is ready for admin verification.")


if __name__ == '__main__':
    seed_database()
