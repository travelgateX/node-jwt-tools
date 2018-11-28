export class PermissionTable {
    // Product-->object-->Permission-->Groups
    permissions: Map<string, Map<string, Map<string, Map<string, string>>>>;
    isAdmin: boolean;
    bearer: string;
    // Group hierarchy tree
    groups: Map<string, GroupTree>;
    // Member identifier
    memberId: string;
    errorMessage: string;
}

export interface Jwt {
    // Group Code
    c: string;
    // Group Desendents
    g: Jwt[];
    // Group Type
    t: string;
    //Group Permissions
    p: Map<string, Map<string, string[]>>;
    // Additional Group
    a: Map<string, Map<string, Map<string, string[]>>>;
}

export interface GroupTree {
    groupType: string;
    groups: Map<string, GroupTree>;
}