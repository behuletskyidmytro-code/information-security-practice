
from app.database import SessionLocal
from app.models import User, Role, Permission
from app.security import hash_password

db = SessionLocal()

try:
    role_permissions = {
        "admin": ["users:read", "users:write", "students:read", "teachers:read"],
        "teacher": ["students:read", "teachers:read"],
        "student": ["students:read"],
    }

    roles = {}

    for role_name, permission_names in role_permissions.items():
        role = db.query(Role).filter_by(name=role_name).first()

        if role is None:
            role = Role(name=role_name)
            db.add(role)
            db.flush()

        roles[role_name] = role

        for permission_name in permission_names:
            permission = db.query(Permission).filter_by(
                name=permission_name
            ).first()

            if permission is None:
                permission = Permission(name=permission_name)
                db.add(permission)
                db.flush()

            if permission not in role.permissions:
                role.permissions.append(permission)

    accounts = [
        ("admin", "Admin12345!", "admin"),
        ("teacher", "Teacher12345!", "teacher"),
        ("student", "Student12345!", "student"),
    ]

    for username, password, role_name in accounts:
        user = db.query(User).filter_by(username=username).first()

        if user is None:
            user = User(
                username=username,
                password_hash=hash_password(password),
            )
            db.add(user)
            db.flush()

        if roles[role_name] not in user.roles:
            user.roles.append(roles[role_name])

    db.commit()
    print("Test users and RBAC permissions created successfully")

except Exception:
    db.rollback()
    raise

finally:
    db.close()
