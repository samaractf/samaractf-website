from functools import wraps
from flask import abort
from flask_login import current_user
from app.models import Permission



def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if not current_user.can(permission):
                    abort(403)
            except AttributeError:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permission.ADMIN)(f)

def moderator_required(f):
    return permission_required(Permission.MODERATE)(f)

def write_required(f):
    return permission_required(Permission.WRITE)(f)

def samara_required(f):
    return permission_required(Permission.SAMARA)(f)