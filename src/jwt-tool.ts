import { UserConfig } from './classes/user-config';
import { PermissionTable, Jwt, GroupTree } from './classes/permission-table';
const jwt = require('jsonwebtoken');

// Permissions Constants
const CNST_CREATE = 'c';
const CNST_UPDATE = 'u';
const CNST_DELETE = 'd';
const CNST_READ = 'r';

export function JwtTools(pBearer: string, pAdminGroup: string, pConfig: UserConfig) {
    
    const bearer = pBearer.includes('Bearer ') ? pBearer.split(' ')[1] : pBearer;

    let permissionTable: PermissionTable = {
        bearer: bearer,
        memberId: '',
        isAdmin: false,
        permissions: new Map<string, Map<string, Map<string, Map<string, string>>>>(),
        groups: new Map<string, GroupTree>(),
        errorMessage: null
    };
    _NewPermissionTable(permissionTable, pAdminGroup, pConfig);
    return permissionTable;
}

function _NewPermissionTable(permissionTable: PermissionTable, pAdminGroup: string, pConfig: UserConfig) {

    try {
        const iamMemberId = _GetIamAndMemberId(permissionTable.bearer, pConfig);
        if (iamMemberId[0]) {
            permissionTable.memberId = iamMemberId[1];
            const jwt: Jwt = iamMemberId[0];
            _BuildPermissions(permissionTable, new Array(jwt), permissionTable.groups, pAdminGroup);
        }
        else {
            permissionTable.errorMessage = 'Invalid iam structure.';
        }
    } catch (err) {
        permissionTable.errorMessage = err.message;
        permissionTable.permissions = null;
        permissionTable.groups = null;
        return;
    }
}

//Return the IAM and MemberID claims value
function _GetIamAndMemberId(pJwt: string, pConfig: UserConfig) {

    const decoded = jwt.decode(pJwt, { complete: true });
    let iam = null;
    let memberId = null;
    for (var claimKey of Object.keys(decoded.payload)) {
        if (claimKey === pConfig.claimUrl + pConfig.claimIam) {
            iam = decoded.payload[claimKey][0];
        } else if (claimKey === pConfig.claimUrl + pConfig.claimMemberId) {
            memberId = decoded.payload[claimKey];
        }
        if (iam && memberId) { break; }
    }
    return Object.freeze([iam, memberId]);
}

function _BuildPermissions(permissionTable: PermissionTable, pGroups: Jwt[], pTree: Map<string, GroupTree>, pAdminGroup: string) {

    if (!pGroups) { return; }

    pGroups.forEach(group => {

        //Check if the data (type and code) is filled.
        if (!group.c || !group.t) { return; }

        //Fill the tree with the data on the group
        pTree.set(group.c, {
            groupType: group.t,
            groups: new Map<string, GroupTree>()
        });

        //Check additional permissions.
        // In additional level, we have an extra level above products, we iterate on them and use the same function.
        if (group.a) {
            for (const [key, value] of Object.entries(group.a)) {
            _FillPermissionsFromProducts(value, permissionTable.permissions, key, pAdminGroup);
            }
        }

        //Check the Products
        permissionTable.isAdmin = _FillPermissionsFromProducts(group.p, permissionTable.permissions, group.c, pAdminGroup);

        //Call recursivity
        let groupTree: Map<string, GroupTree> = pTree.get(group.c).groups;
        _BuildPermissions(permissionTable, group.g, groupTree, pAdminGroup);
    });
}

function _FillPermissionsFromProducts(pProducts: Map<string, Map<string, string[]>>,
    pPermissions: Map<string, Map<string, Map<string, Map<string, string>>>>,
    pGroup: string,
    pAdminGroup: string) {

    if (!pProducts) { return false; }

    let ret = false;

    for (const [key, value] of Object.entries(pProducts)) {
        //If we dont have the key, or the key with a null value, we initialize it
        if (!pPermissions.has(key) || !pPermissions.get(key)) {
            pPermissions.set(key, new Map<string, Map<string, Map<string, string>>>());
        }

        const p: Map<string, Map<string, Map<string, string>>> = pPermissions.get(key);

        if (value) {
            for (const [key2, value2] of Object.entries(value)) {

                let tuple = null;
                if (!p.has(key2)) {
                    p.set(key2, new Map<string, Map<string, string>>());
                }

                tuple = _GetObjects(<string[]>value2, pGroup, p.get(key2), pAdminGroup);
                pPermissions.get(key).set(key2, tuple[1]);
                if (tuple[0]) {
                    ret = tuple[0];
                }
            }
        }
    }
    return ret;
}

function _GetObjects(pRoles: Array<string>, pGroup: string, pP: Map<string, Map<string, string>>, pAdminGroup: string) {
    let isAdmin = false;

    pRoles.forEach(rol => {
        
        _ExtractPermissions(rol).forEach(pm => {
            if (!pP.has(pm)) {
                pP.set(pm, new Map<string, string>());
            }
            if (!pP.get(pm).has(pGroup)) {
                pP.get(pm).set(pGroup, '');
            }
        });
    });

    isAdmin = ((pAdminGroup == pGroup) || (pP && pP.has(CNST_CREATE) && pP.has(CNST_READ) && pP.has(CNST_UPDATE) && pP.has(CNST_DELETE)));
    return Object.freeze([isAdmin, pP]);
}

function _ExtractPermissions(p: string) {
    let enabled = false;
    let permissions: string[] = [];
    let otherPermissions: string[] = [];

    for (let i = 0; i < p.length; i++) {
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


