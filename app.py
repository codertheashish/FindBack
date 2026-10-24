
import os
from flask import Flask, render_template, send_from_directory, abort
from config import Config
from models import init_db, get_reports, get_db


def mask_mobile(value):
    value = str(value or "")
    return ("•" * max(0, len(value) - 4) + value[-4:]) if value else "—"


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

        # Vercel serverless functions have a read-only application filesystem.
    # /tmp is writable but temporary.
    if os.environ.get("VERCEL"):
        base_dir = "/tmp/findback"
        app.config["UPLOAD_FOLDER"] = os.path.join(base_dir, "uploads")
        app.config["DATABASE"] = os.path.join(
            base_dir, "instance", "findback.db"
        )

    if test_config:
        app.config.update(test_config)

    # Ensure uploads and instance directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(
        os.path.dirname(os.path.abspath(app.config["DATABASE"])),
        exist_ok=True,
    )

    # Initialize database and apply migrations
    init_db(app.config["DATABASE"])

    # Make sure an admin account exists on a fresh database (Vercel /tmp, new PythonAnywhere install).
    # Username: SEED_ADMIN_USERNAME (default "admin"),
    # password: SEED_ADMIN_PASSWORD).
    if os.getenv("SEED_ADMIN_PASSWORD") and not app.config.get("TESTING"):
        from models import create_staff, ROLE_ADMIN
        _conn = get_db(app.config["DATABASE"])
        try:
            _has_admin = _conn.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin'"
            ).fetchone()[0]
        finally:
            _conn.close()
        if not _has_admin:
            create_staff(
                os.getenv("SEED_ADMIN_USERNAME", "admin"),
                "Chief Campus Security",
                ROLE_ADMIN,
                os.getenv("SEED_ADMIN_PASSWORD"),
                db_path=app.config["DATABASE"],
            )

    # Security configuration
    from security import init_security
    init_security(app)

    app.jinja_env.filters["mask_mobile"] = mask_mobile

    # Register Blueprints
    from auth import auth_bp
    from reports import reports_bp
    from claims import claims_bp
    from admin import admin_bp
    from teacher import teacher_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(claims_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(teacher_bp)

    # Home route
    @app.route("/")
    def index():
        conn = get_db(app.config["DATABASE"])
        try:
            cur = conn.cursor()

            cur.execute(
                "SELECT COUNT(*) FROM reports WHERE report_type = 'lost'"
            )
            lost_count = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM reports WHERE report_type = 'found'"
            )
            found_count = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM reports WHERE status = 'Returned'"
            )
            returned_count = cur.fetchone()[0]
        finally:
            conn.close()

        recent_lost = get_reports(
            report_type="lost",
            limit=4,
            db_path=app.config["DATABASE"],
        )
        recent_found = get_reports(
            report_type="found",
            limit=4,
            db_path=app.config["DATABASE"],
        )

        return render_template(
            "index.html",
            lost_count=lost_count,
            found_count=found_count,
            returned_count=returned_count,
            recent_lost=recent_lost,
            recent_found=recent_found,
        )

    # Serve only allowed uploaded file extensions
    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename):
        ext = (
            filename.rsplit(".", 1)[-1].lower()
            if "." in filename
            else ""
        )

        if ext not in app.config["ALLOWED_EXTENSIONS"]:
            abort(404)

        return send_from_directory(
            app.config["UPLOAD_FOLDER"],
            filename,
        )

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("500.html"), 500

    return app


# Vercel requires a top-level Flask application instance.
app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in (
        "1", "true", "yes"
    )

    print(f"Starting FindBack portal on http://{host}:{port} ...")
    app.run(host=host, port=port, debug=debug)
