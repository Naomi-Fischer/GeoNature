"""
Decorators to protects routes with permissions
"""
from functools import wraps
from warnings import warn

from flask import request, g
from werkzeug.exceptions import Unauthorized, Forbidden

from geonature.core.gn_permissions.tools import get_scopes_by_action


def login_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if g.current_user is None:
            raise Unauthorized
        return view_func(*args, **kwargs)

    return decorated_view


def check_cruved_scope(
    action,
    module_code=None,
    object_code=None,
    *,
    get_scope=False,
):
    """
    Decorator to protect routes with SCOPE CRUVED
    The decorator first check if the user is connected
    and then return the max user SCOPE permission for the action in parameter
    The decorator manages herited CRUVED from user's group and parent module (GeoNature)

    Parameters:
        action(string): the requested action of the route <'C', 'R', 'U', 'V', 'E', 'D'>
        module_code(string): the code of the module (gn_commons.t_modules) (e.g. 'OCCTAX') for the requested permission
        object_code(string): the code of the object (gn_permissions.t_object) for the requested permission (e.g. 'PERMISSIONS')
        get_scope(boolean): does the decorator should add the scope to view kwargs
    """

    def _check_cruved_scope(view_func):
        @wraps(view_func)
        def decorated_view(*args, **kwargs):
            if g.current_user is None:
                raise Unauthorized
            scope = get_scopes_by_action(module_code=module_code, object_code=object_code)[action]
            if not scope:
                message = f"User {g.current_user.id_role} can not {action} in {module_code}"
                if object_code:
                    message += f" on {object_code}"
                raise Forbidden(description=message)
            if get_scope:
                kwargs["scope"] = scope
            return view_func(*args, **kwargs)

        return decorated_view

    return _check_cruved_scope
