"""Sample auth module — used as the target file in GATE-M demos."""


def validate_user(user):
    return user.is_active


def get_user_role(user):
    return user.role


def logout(user):
    user.session_token = None
