"use strict";
var __values = (this && this.__values) || function (o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator], i = 0;
    if (m) return m.call(o);
    return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
};
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
var jwt = require('jsonwebtoken');
// Permissions Constants
var CNST_CREATE = 'c';
var CNST_UPDATE = 'u';
var CNST_DELETE = 'd';
var CNST_READ = 'r';
function JwtTools(pBearer, pAdminGroup, pConfig) {
    var bearer = pBearer.includes('Bearer ') ? pBearer.split(' ')[1] : pBearer;
    var permissionTable = {
        bearer: bearer,
        memberId: '',
        isAdmin: false,
        permissions: new Map(),
        groups: new Map(),
        errorMessage: null
    };
    _NewPermissionTable(permissionTable, pAdminGroup, pConfig);
    return permissionTable;
}
exports.JwtTools = JwtTools;
function _NewPermissionTable(permissionTable, pAdminGroup, pConfig) {
    try {
        var iamMemberId = _GetIamAndMemberId(permissionTable.bearer, pConfig);
        if (iamMemberId[0]) {
            permissionTable.memberId = iamMemberId[1];
            var jwt_1 = iamMemberId[0];
            _BuildPermissions(permissionTable, new Array(jwt_1), permissionTable.groups, pAdminGroup);
        }
        else {
            permissionTable.errorMessage = 'Invalid iam structure.';
        }
    }
    catch (err) {
        permissionTable.errorMessage = err.message;
        permissionTable.permissions = null;
        permissionTable.groups = null;
        return;
    }
}
//Return the IAM and MemberID claims value
function _GetIamAndMemberId(pJwt, pConfig) {
    var e_1, _a;
    var decoded = jwt.decode(pJwt, { complete: true });
    var iam = null;
    var memberId = null;
    try {
        for (var _b = __values(Object.keys(decoded.payload)), _c = _b.next(); !_c.done; _c = _b.next()) {
            var claimKey = _c.value;
            if (claimKey === pConfig.claimUrl + pConfig.claimIam) {
                iam = decoded.payload[claimKey][0];
            }
            else if (claimKey === pConfig.claimUrl + pConfig.claimMemberId) {
                memberId = decoded.payload[claimKey];
            }
            if (iam && memberId) {
                break;
            }
        }
    }
    catch (e_1_1) { e_1 = { error: e_1_1 }; }
    finally {
        try {
            if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
        }
        finally { if (e_1) throw e_1.error; }
    }
    return Object.freeze([iam, memberId]);
}
function _BuildPermissions(permissionTable, pGroups, pTree, pAdminGroup) {
    if (!pGroups) {
        return;
    }
    pGroups.forEach(function (group) {
        var e_2, _a;
        //Check if the data (type and code) is filled.
        if (!group.c || !group.t) {
            return;
        }
        //Fill the tree with the data on the group
        pTree.set(group.c, {
            groupType: group.t,
            groups: new Map()
        });
        //Check additional permissions.
        // In additional level, we have an extra level above products, we iterate on them and use the same function.
        if (group.a) {
            try {
                for (var _b = __values(Object.entries(group.a)), _c = _b.next(); !_c.done; _c = _b.next()) {
                    var _d = __read(_c.value, 2), key = _d[0], value = _d[1];
                    _FillPermissionsFromProducts(value, permissionTable.permissions, key, pAdminGroup);
                }
            }
            catch (e_2_1) { e_2 = { error: e_2_1 }; }
            finally {
                try {
                    if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                }
                finally { if (e_2) throw e_2.error; }
            }
        }
        //Check the Products
        permissionTable.isAdmin = _FillPermissionsFromProducts(group.p, permissionTable.permissions, group.c, pAdminGroup);
        //Call recursivity
        var groupTree = pTree.get(group.c).groups;
        _BuildPermissions(permissionTable, group.g, groupTree, pAdminGroup);
    });
}
function _FillPermissionsFromProducts(pProducts, pPermissions, pGroup, pAdminGroup) {
    var e_3, _a, e_4, _b;
    if (!pProducts) {
        return false;
    }
    var ret = false;
    try {
        for (var _c = __values(Object.entries(pProducts)), _d = _c.next(); !_d.done; _d = _c.next()) {
            var _e = __read(_d.value, 2), key = _e[0], value = _e[1];
            //If we dont have the key, or the key with a null value, we initialize it
            if (!pPermissions.has(key) || !pPermissions.get(key)) {
                pPermissions.set(key, new Map());
            }
            var p = pPermissions.get(key);
            if (value) {
                try {
                    for (var _f = __values(Object.entries(value)), _g = _f.next(); !_g.done; _g = _f.next()) {
                        var _h = __read(_g.value, 2), key2 = _h[0], value2 = _h[1];
                        var tuple = null;
                        if (!p.has(key2)) {
                            p.set(key2, new Map());
                        }
                        tuple = _GetObjects(value2, pGroup, p.get(key2), pAdminGroup);
                        pPermissions.get(key).set(key2, tuple[1]);
                        if (tuple[0]) {
                            ret = tuple[0];
                        }
                    }
                }
                catch (e_4_1) { e_4 = { error: e_4_1 }; }
                finally {
                    try {
                        if (_g && !_g.done && (_b = _f.return)) _b.call(_f);
                    }
                    finally { if (e_4) throw e_4.error; }
                }
            }
        }
    }
    catch (e_3_1) { e_3 = { error: e_3_1 }; }
    finally {
        try {
            if (_d && !_d.done && (_a = _c.return)) _a.call(_c);
        }
        finally { if (e_3) throw e_3.error; }
    }
    return ret;
}
function _GetObjects(pRoles, pGroup, pP, pAdminGroup) {
    var isAdmin = false;
    pRoles.forEach(function (rol) {
        _ExtractPermissions(rol).forEach(function (pm) {
            if (!pP.has(pm)) {
                pP.set(pm, new Map());
            }
            if (!pP.get(pm).has(pGroup)) {
                pP.get(pm).set(pGroup, '');
            }
        });
    });
    isAdmin = ((pAdminGroup == pGroup) || (pP && pP.has(CNST_CREATE) && pP.has(CNST_READ) && pP.has(CNST_UPDATE) && pP.has(CNST_DELETE)));
    return Object.freeze([isAdmin, pP]);
}
function _ExtractPermissions(p) {
    var enabled = false;
    var permissions = [];
    var otherPermissions = [];
    for (var i = 0; i < p.length; i++) {
        switch (p[i]) {
            case 'c':
                permissions.push(CNST_CREATE);
                break;
            case 'r':
                permissions.push(CNST_READ);
                break;
            case 'u':
                permissions.push(CNST_UPDATE);
                break;
            case 'd':
                permissions.push(CNST_DELETE);
                break;
            case '1':
                enabled = true;
                break;
            default:
                otherPermissions.push(p[i]);
                break;
        }
    }
    if (otherPermissions.length > 0) {
        permissions = permissions.concat(otherPermissions);
    }
    return enabled ? permissions : [];
}
