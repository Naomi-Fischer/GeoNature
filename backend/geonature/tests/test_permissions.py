from collections import ChainMap
from itertools import product

import pytest

from geonature.core.gn_commons.models import TModules
from geonature.core.gn_permissions.models import (
    TObjects,
    TFilters,
    TActions,
    BibFiltersType,
    CorRoleActionFilterModuleObject as Permission,
)
from geonature.core.gn_permissions.tools import get_scopes_by_action
from geonature.utils.env import db

from pypnusershub.db.models import User


@pytest.fixture(scope="class")
def actions():
    return {action.code_action: action for action in TActions.query.all()}


@pytest.fixture(scope="class")
def scopes():
    scope_type = BibFiltersType.query.filter_by(code_filter_type="SCOPE").one()
    return {f.value_filter: f for f in TFilters.query.filter_by(filter_type=scope_type).all()}


def create_module(label):
    return TModules(
        module_code=label.upper(),
        module_label=label,
        module_path=label,
        active_frontend=False,
        active_backend=False,
    )


@pytest.fixture(scope="class")
def module_gn():
    return TModules.query.filter_by(module_code="GEONATURE").one()


@pytest.fixture(scope="class")
def object_all():
    return TObjects.query.filter_by(code_object="ALL").one()


@pytest.fixture(scope="class")
def object_a():
    obj = TObjects(code_object="object_a")
    return obj


@pytest.fixture(scope="class")
def object_b():
    obj = TObjects(code_object="object_b")
    return obj


@pytest.fixture(scope="class")
def module_a():
    with db.session.begin_nested():
        module = create_module("module_a")
        db.session.add(module)
    return module


@pytest.fixture(scope="class")
def module_b():
    with db.session.begin_nested():
        module = create_module("module_b")
        db.session.add(module)
    return module


@pytest.fixture()
def groups():
    groups = {
        "g1": User(groupe=True),
        "g2": User(groupe=True),
    }
    with db.session.begin_nested():
        for group in groups.values():
            db.session.add(group)
    return groups


@pytest.fixture()
def roles(groups):
    roles = {
        "r1": User(),
        "r2": User(),
        "g1_r1": User(groups=[groups["g1"]]),
        "g1_r2": User(groups=[groups["g1"]]),
        "g2_r1": User(groups=[groups["g2"]]),
        "g2_r2": User(groups=[groups["g2"]]),
        "g12_r1": User(groups=[groups["g1"], groups["g2"]]),
        "g12_r2": User(groups=[groups["g1"], groups["g2"]]),
    }
    roles.update(groups)
    with db.session.begin_nested():
        for role in roles.values():
            db.session.add(role)
    return roles


def cruved_dict(scopes):
    scopes = str(scopes)
    return {
        "C": int(scopes[0]),
        "R": int(scopes[1]),
        "U": int(scopes[2]),
        "V": int(scopes[3]),
        "E": int(scopes[4]),
        "D": int(scopes[5]),
    }


@pytest.fixture()
def permissions(roles, groups, actions, scopes, module_gn):
    roles = ChainMap(roles, groups)

    def _permissions(role, cruved, *, module=module_gn, **kwargs):
        role = roles[role]
        with db.session.begin_nested():
            for a, s in zip("CRUVED", cruved):
                if s == "-":
                    continue
                db.session.add(
                    Permission(
                        role=role, action=actions[a], filter=scopes[s], module=module, **kwargs
                    )
                )

    return _permissions


@pytest.fixture()
def assert_cruved(roles):
    def _assert_cruved(role, cruved, module=None, object=None):
        role = roles[role]
        module_code = module.module_code if module else None
        object_code = object.code_object if object else None
        assert get_scopes_by_action(
            id_role=role.id_role, module_code=module_code, object_code=object_code
        ) == cruved_dict(cruved)

    return _assert_cruved


@pytest.mark.usefixtures("temporary_transaction")
class TestPermissions:
    def test_no_right(self, assert_cruved, module_gn, module_a, object_a):
        assert_cruved("r1", "000000")
        assert_cruved("g1_r1", "000000", module_a)
        assert_cruved("r1", "000000", module_gn, object_a)
        assert_cruved("r1", "000000", module_a, object_a)

    def test_module_perm(self, permissions, assert_cruved, module_gn, module_a, module_b):
        permissions("r1", "1----2", module=module_gn)
        permissions("r1", "-1---1", module=module_a)
        permissions("r1", "--1---", module=module_b)

        assert_cruved("r1", "100002")
        assert_cruved("r1", "010001", module_a)
        assert_cruved("r1", "001000", module_b)
        assert_cruved("r2", "000000", module_a)

    def test_no_module_no_object_specified(
        self, permissions, assert_cruved, module_gn, object_all, module_a, object_a
    ):
        permissions("r1", "11----", module=module_gn, object=object_all)
        permissions("r1", "--11--", module=module_gn, object=object_a)
        permissions("r1", "----11", module=module_a, object=object_all)

        assert_cruved("r1", "110000", module=module_gn)
        assert_cruved("r1", "110000", object=object_all)
        assert_cruved("r1", "110000")

        assert_cruved("r1", "001100", object=object_a)

        assert_cruved("r1", "000011", module=module_a)

    def test_group_inheritance(self, permissions, assert_cruved, module_gn, module_a):
        permissions("g1", "0123--", module=module_a)

        assert_cruved("r1", "000000")
        assert_cruved("r1", "000000", module_a)
        assert_cruved("g1_r1", "000000")
        assert_cruved("g1_r1", "012300", module_a)
        assert_cruved("g2_r1", "000000")
        assert_cruved("g2_r1", "000000", module_a)

    def test_user_and_group_perm(self, permissions, assert_cruved, module_a):
        permissions("g1", "0123--", module=module_a)
        permissions("g1_r1", "1023--", module=module_a)

        assert_cruved("g1_r1", "112300", module=module_a)  # max of user and group permission

    def test_multi_groups_one_perm(self, permissions, assert_cruved, module_a):
        permissions("g1", "0123--", module=module_a)

        assert_cruved("g1_r1", "012300", module_a)
        assert_cruved("g12_r1", "012300", module_a)
        assert_cruved("g2_r1", "000000", module_a)

    def test_multi_groups_multi_perms(self, permissions, assert_cruved, module_a):
        permissions("g1", "12131-", module=module_a)
        permissions("g2", "0121-3", module=module_a)

        assert_cruved("g1_r1", "121310", module_a)
        assert_cruved("g2_r1", "012103", module_a)
        assert_cruved("g12_r1", "122313", module_a)  # max of both groups permissions

    def test_object_perm(self, permissions, assert_cruved, module_a, module_b, object_a, object_b):
        permissions("r1", "1----2", module=module_a)
        permissions("r1", "-1---1", module=module_a, object=object_a)
        permissions("r1", "--1---", module=module_b, object=object_a)
        permissions("r1", "---1--", module=module_a, object=object_b)

        assert_cruved("r1", "000000")
        assert_cruved("r1", "100002", module_a)
        assert_cruved("r1", "010001", module_a, object_a)
        assert_cruved("r1", "001000", module_b, object_a)
        assert_cruved("r1", "000100", module_a, object_b)

    def test_module_objet_inheritance(
        self,
        permissions,
        assert_cruved,
        module_gn,
        module_a,
        module_b,
        object_all,
        object_a,
        object_b,
    ):
        # Permissions for users "g1_r1" and "g1_r2", associated to the group "g1"
        # For "g1"
        permissions("g1", "121-1-", module=module_gn, object=object_all)  # [g1_gn]
        permissions("g1", "0121-2", module=module_a, object=object_all)  # [g1_a]
        permissions("g1", "1-1---", module=module_a, object=object_a)  # [g1_a_a]
        permissions("g1", "--2--1", module=module_a, object=object_b)  # [g1_a_b]
        # For "g1_r1"
        permissions("g1_r1", "132-03", module=module_gn, object=object_all)  # [g1_r1_gn]
        permissions("g1_r1", "-2---1", module=module_a, object=object_all)  # [g1_r1_a]
        permissions("g1_r1", "0-3-03", module=module_a, object=object_a)  # [g1_r1_a_a]
        # For "g1_r2"
        permissions("g1_r2", "--31-0", module=module_a, object=object_all)  # [g1_r2_a]
        permissions("g1_r2", "--31-0", module=module_a, object=object_b)  # [g1_r2_a_b]

        # Permissions for one user "r1", not associated to any group
        permissions("r1", "121-31", module=module_gn, object=object_all)  # [r1_gn]
        permissions("r1", "0123--", module=module_a, object=object_all)  # [r1_a]
        permissions("r1", "0121-3", module=module_b, object=object_all)  # [r1_b]
        permissions("r1", "1-1---", module=module_a, object=object_a)  # [r1_a_a]
        permissions("r1", "--2---", module=module_a, object=object_b)  # [r1_a_b]
        permissions("r1", "----2-", module=module_b, object=object_a)  # [r1_b_a]
        permissions("r1", "-1----", module=module_b, object=object_b)  # [r1_b_b]

        # Permissions to get group "g2"
        permissions("g2", "------")

        is_with_inheritance_modules_objects = False

        ## Permissions added to keep "GEONATURE" module and "ALL" object inheritance
        if is_with_inheritance_modules_objects:
            ## Inheritances for user "r1" (module and object inheritances, without group inheritance interaction)
            # Inheritances from module "GEONATURE"
            #   - from [r1_gn]]
            permissions(
                "r1", "----31", module=module_a, object=object_all
            )  # [r1_'1] given [r1_a]]
            permissions(
                "r1", "----3-", module=module_b, object=object_all
            )  # [r1_'2] given [r1_b]]
            # Inheritances from module "A" and object "ALL"
            #   - from [r1_a]]
            permissions("r1", "-1-3--", module=module_a, object=object_a)  # given [r1_a_a]
            permissions("r1", "01-3--", module=module_a, object=object_b)  # given [r1_a_b]
            #   - from [r1_b]]
            permissions("r1", "0121-3", module=module_b, object=object_a)  # given [r1_b_a]
            permissions("r1", "0-21-3", module=module_b, object=object_b)  # given [r1_b_b]
            # Inheritances from module "GEONATURE" and object "ALL"
            #   - from [r1_'1]
            permissions("r1", "----31", module=module_a, object=object_a)  # given [r1_a_a]
            permissions("r1", "----31", module=module_a, object=object_b)  # given [r1_a_b]
            #   - from [r1_'2]
            permissions("r1", "------", module=module_b, object=object_a)  # given [r1_b_a]
            permissions("r1", "----3-", module=module_b, object=object_b)  # given [r1_b_b]

        ## Testing computed scope permissions
        # With additional permissions to inherit "GEONATURE" and "ALL"
        if is_with_inheritance_modules_objects:
            ## Users "g1_r1" and "g1_r2"
            ##  Some permissions defined for the user AND some inherited from groups
            ##  (modules and objects inheritances, with group inheritances interaction)
            # For "g1_r1"
            assert_cruved("g1_r1", "132013")  # given [g1_r1_gn] and [g1_gn]
            assert_cruved("g1_r1", "0221-2", module=module_a)  # given [g1_r1_a] and [g1_a]
            assert_cruved(
                "g1_r1", "103003", module=module_a, object=object_a
            )  # given [g1_r1_a_a] and [g1_a_a]
            assert_cruved(
                "g1_r1", "022111", module=module_a, object=object_b
            )  # given [g1_a_b], then [g1_r1_a] and [g1_a], then [g1_r1_gn] and [g1_gn]
            assert_cruved("g1_r1", "132013", module=module_b)  # given [g1_r1_gn] and [g1_gn]
            assert_cruved(
                "g1_r1", "132013", module=module_b, object=object_a
            )  # given [g1_r1_gn] and [g1_gn]
            assert_cruved(
                "g1_r1", "132013", module=module_b, object=object_b
            )  # given [g1_r1_gn] and [g1_gn]
            # For "g1_r2"
            assert_cruved("g1_r2", "121010")  # given [g1_gn]
            assert_cruved(
                "g1_r2", "013112", module=module_a
            )  # given [g1_r2_a] and [g1_a], then [g1_gn]
            assert_cruved(
                "g1_r2", "111112", module=module_a, object=object_a
            )  # given [g1_a_a], then [g1_r2_a] and [g1_a], then [g1_gn]
            assert_cruved(
                "g1_r2", "013111", module=module_a, object=object_b
            )  # given [g1_r2_a_b] and [g1_a_b], then [g1_r2_a] and [g1_a], then [g1_gn]
            assert_cruved("g1_r2", "121010", module=module_b)  # given [g1_gn]
            assert_cruved("g1_r2", "121010", module=module_b, object=object_a)  # given [g1_gn]
            assert_cruved("g1_r2", "121010", module=module_b, object=object_b)  # given [g1_gn]

            ## Users "g12_r1" and "g12_r2"
            ##  No permission defined for the user BUT some inherited from groups
            ##  (group inheritances interaction)
            # For "g12_r1"
            assert_cruved("g12_r1", "121010")  # given [g1_gn]
            assert_cruved("g12_r1", "012112", module=module_a)  # given [g1_a], then [g1_gn]
            assert_cruved(
                "g12_r1", "111112", module=module_a, object=object_a
            )  # given [g1_a_a], then [g1_a], then [g1_gn]
            assert_cruved(
                "g12_r1", "012111", module=module_a, object=object_b
            )  # given [g1_a_b], then [g1_a], then [g1_gn]
            assert_cruved("g12_r1", "121010", module=module_b)  # given [g1_gn]
            assert_cruved("g12_r1", "121010", module=module_b, object=object_a)  # given [g1_gn]
            assert_cruved("g12_r1", "121010", module=module_b, object=object_b)  # given [g1_gn]
            # For "g12_r2" (same as for "g12_r1")
            assert_cruved("g12_r2", "121010")  # given [g1_gn]

            ## Users "r2" and "g2_r1" and Group "g2"
            ## Neither any permission defined for the user NOR any inherited from groups
            ## (nothing)
            # For "r2"
            assert_cruved("r2", "000000")  # nothing
            assert_cruved("r2", "000000", module=module_a)  # nothing
            assert_cruved("r2", "000000", module=module_a, object=object_a)  # nothing
            assert_cruved("r2", "000000", module=module_a, object=object_b)  # nothing
            assert_cruved("r2", "000000", module=module_b)  # nothing
            assert_cruved("r2", "000000", module=module_b, object=object_a)  # nothing
            assert_cruved("r2", "000000", module=module_b, object=object_b)  # nothing
            # For "g2_r1" (same as for "r2")
            assert_cruved("g2_r1", "000000")  # nothing
            # For "g2" (same as for "r2")
            assert_cruved("g2", "000000")  # nothing

            ## Scope permissions for user "r1" and group "g1"
            ##  Some permissions defined for the user BUT not any inherited from group
            ##  (module and object inheritances, without group inheritance interaction)
            # For "r1"
            assert_cruved("r1", "121031")  # given [r1_gn]
            assert_cruved("r1", "012331", module=module_a)  # given [r1_a], then [r1_gn]
            assert_cruved(
                "r1", "111331", module=module_a, object=object_a
            )  # given [r1_a_a], then [r1_a], then [r1_gn]
            assert_cruved(
                "r1", "012331", module=module_a, object=object_b
            )  # given [r1_a_b], then [r1_a], then [r1_gn]
            assert_cruved("r1", "012133", module=module_b)  # given [r1_b], then [r1_gn]
            assert_cruved(
                "r1", "012123", module=module_b, object=object_a
            )  # given [r1_b_a], then [r1_b], then [r1_gn]
            assert_cruved(
                "r1", "012133", module=module_b, object=object_b
            )  # given [r1_b_b], then [r1_b], then [r1_gn]
            # For "g1"
            assert_cruved("g1", "121010")  # given [g1_gn]
            assert_cruved("g1", "012112", module=module_a)  # given [g1_a], then [g1_gn]
            assert_cruved(
                "g1", "111112", module=module_a, object=object_a
            )  # given [g1_a_a], then [g1_a], then [g1_gn]
            assert_cruved(
                "g1", "012111", module=module_a, object=object_b
            )  # given [g1_a_b], then [g1_a], then [g1_gn]
            assert_cruved("g1", "121010", module=module_b)  # given [g1_gn]
            assert_cruved("g1", "121010", module=module_b, object=object_a)  # given [g1_gn]
            assert_cruved("g1", "121010", module=module_b, object=object_b)  # given [g1_gn]
        # Without additional permissions to inherit "GEONATURE" and "ALL"
        # --> Still inheritance group->user
        else:
            ## Users "g1_r1" and "g1_r2"
            ##  Some permissions defined for the user AND some inherited from groups
            # For "g1_r1"
            assert_cruved("g1_r1", "132013")  # given [g1_r1_gn] and [g1_gn]
            assert_cruved("g1_r1", "022102", module=module_a)  # given [g1_r1_a] and [g1_a]
            assert_cruved(
                "g1_r1", "103003", module=module_a, object=object_a
            )  # given [g1_r1_a_a] and [g1_a_a]
            assert_cruved("g1_r1", "002001", module=module_a, object=object_b)  # given [g1_a_b]
            assert_cruved("g1_r1", "000000", module=module_b)  # nothing
            assert_cruved("g1_r1", "000000", module=module_b, object=object_a)  # nothing
            assert_cruved("g1_r1", "000000", module=module_b, object=object_b)  # nothing
            # For "g1_r2"
            assert_cruved("g1_r2", "121010")  # given [g1_gn]
            assert_cruved("g1_r2", "013102", module=module_a)  # given [g1_r2_a] and [g1_a]
            assert_cruved("g1_r2", "101000", module=module_a, object=object_a)  # given [g1_a_a]
            assert_cruved(
                "g1_r2", "003101", module=module_a, object=object_b
            )  # given [g1_r2_a_b] and [g1_a_b]
            assert_cruved("g1_r2", "000000", module=module_b)  # nothing
            assert_cruved("g1_r2", "000000", module=module_b, object=object_a)  # nothing
            assert_cruved("g1_r2", "000000", module=module_b, object=object_b)  # nothing

            ## Users "g1_r2", "g12_r1" and "g12_r2"
            ##  No permission defined for the user BUT some inherited from groups
            # For "g12_r1"
            assert_cruved("g12_r1", "121010")  # given [g1_gn]
            assert_cruved("g12_r1", "012102", module=module_a)  # given [g1_a]
            assert_cruved("g12_r1", "101000", module=module_a, object=object_a)  # given [g1_a_a]
            assert_cruved("g12_r1", "002001", module=module_a, object=object_b)  # given [g1_a_b]
            assert_cruved("g12_r1", "000000", module=module_b)  # nothing
            assert_cruved("g12_r1", "000000", module=module_b, object=object_a)  # nothing
            assert_cruved("g12_r1", "000000", module=module_b, object=object_b)  # nothing
            # For "g12_r2" (same as for "g12_r1")
            assert_cruved("g12_r2", "121010")  # given [g1_gn]

            ## Users "r2" and "g2_r1" and Group "g2"
            ## Neither any permission defined for the user NOR any inherited from groups
            # For "r2"
            assert_cruved("r2", "000000")  # nothing
            assert_cruved("r2", "000000", module=module_a)  # nothing
            assert_cruved("r2", "000000", module=module_a, object=object_a)  # nothing
            assert_cruved("r2", "000000", module=module_a, object=object_b)  # nothing
            assert_cruved("r2", "000000", module=module_b)  # nothing
            assert_cruved("r2", "000000", module=module_b, object=object_a)  # nothing
            assert_cruved("r2", "000000", module=module_b, object=object_b)  # nothing
            # For "g2_r1" (same as for "r2")
            assert_cruved("g2_r1", "000000")  # nothing
            # For "g2" (same as for "r2")
            # assert_cruved("g2", "000000")  # nothing

            ## Scope permissions for user "r1" and group "g1"
            ##  Some permissions defined for the user BUT not any inherited from group
            # For "r1"
            assert_cruved("r1", "121031")  # given [r1_gn]
            assert_cruved("r1", "012300", module=module_a)  # given [r1_a]
            assert_cruved("r1", "101000", module=module_a, object=object_a)  # given [r1_a_a]
            assert_cruved("r1", "002000", module=module_a, object=object_b)  # given [r1_a_b]
            assert_cruved("r1", "012103", module=module_b)  # given [r1_b]
            assert_cruved("r1", "000020", module=module_b, object=object_a)  # given [r1_b_a]
            assert_cruved("r1", "010000", module=module_b, object=object_b)  # given [r1_b_b]
            # For "g1"
            assert_cruved("g1", "121010")  # given [g1_gn]
            assert_cruved("g1", "0121020", module=module_a)  # given [g1_a]
            assert_cruved("g1", "101000", module=module_a, object=object_a)  # given [g1_a_a]
            assert_cruved("g1", "002001", module=module_a, object=object_b)  # given [g1_a_b]
            assert_cruved("g1", "000000", module=module_b)  # nothing
            assert_cruved("g1", "000000", module=module_b, object=object_a)  # nothing
            assert_cruved("g1", "000000", module=module_b, object=object_b)  # nothing
