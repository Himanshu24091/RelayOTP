import os
from flask import Flask, render_template, session, jsonify, request, redirect, url_for, flash
from config import Config
from utils.db import init_db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Session configuration
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    if app.config.get('FLASK_ENV') == 'production':
        app.config['SESSION_COOKIE_SECURE'] = True

    # Support Railway and reverse proxy SSL termination
    if app.config.get('FLASK_ENV') == 'production' or os.getenv('RAILWAY_ENVIRONMENT'):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize Database Schema
    with app.app_context():
        init_db()

    # Register Blueprints
    from routers.auth_router import auth_bp
    from routers.dashboard_router import dashboard_bp
    from routers.profile_router import profile_bp
    from routers.settings_router import settings_bp
    from routers.admin_router import admin_bp
    from routers.api_router import api_bp
    from routers.help_router import help_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(help_bp)

    @app.before_request
    def enforce_user_session_security():
        # Exclude public assets, health, auth endpoints, and helpdesk from interception
        endpoint = request.endpoint or ''
        if (
            endpoint.startswith('static') or 
            endpoint in ['health_check', 'auth.logout', 'auth.tab_logout', 'auth.login', 'auth.register', 'auth.change_password'] or
            endpoint.startswith('help.')
        ):
            return

        user_id = session.get('user_id')
        if not user_id:
            return

        from utils.db import fetch_one, execute_query
        from datetime import datetime, timezone

        user = fetch_one(
            """
            SELECT id, is_suspended, suspended_until, suspension_reason, must_change_password
            FROM users WHERE id = %s
            """,
            (user_id,)
        )
        if not user:
            session.clear()
            flash("Account record no longer exists. Session closed.", "warning")
            return redirect(url_for('auth.login'))

        if user.get('is_suspended'):
            suspended_until = user.get('suspended_until')
            now = datetime.now(timezone.utc)
            is_active = True
            if suspended_until:
                try:
                    if isinstance(suspended_until, str):
                        dt = datetime.fromisoformat(suspended_until.replace('Z', '+00:00'))
                    else:
                        dt = suspended_until
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if now >= dt:
                        execute_query("UPDATE users SET is_suspended = 0, suspended_until = NULL, suspension_reason = NULL WHERE id = %s", (user_id,))
                        is_active = False
                except Exception:
                    pass

            if is_active:
                reason = user.get('suspension_reason') or 'Suspicious activity detected on office network'
                session.clear()
                flash(f"🚫 Session Terminated: Your account has been suspended by Super Admin. Reason: {reason}", "danger")
                return redirect(url_for('auth.login'))

        if user.get('must_change_password') and endpoint != 'auth.change_password':
            return redirect(url_for('auth.change_password'))

    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'healthy',
            'service': 'RelayOTP Gateway',
            'version': '2.0.0'
        }), 200

    @app.context_processor
    def inject_globals():
        return {
            'app_name': 'RelayOTP',
            'app_version': '2.0.0',
            'is_logged_in': 'user_id' in session,
            'current_user': session.get('username'),
            'is_admin_session': session.get('is_admin', False)
        }

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        if response.headers.get('X-Frame-Options') != 'SAMEORIGIN':
            response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
        
        if 'frame-ancestors' not in response.headers.get('Content-Security-Policy', ''):
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
        if app.config.get('FLASK_ENV') == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('base.html', not_found=True), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('base.html', server_error=True), 500

    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host='0.0.0.0', port=port, debug=debug)
