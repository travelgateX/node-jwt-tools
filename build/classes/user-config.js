"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var UserConfig = /** @class */ (function () {
    function UserConfig(pAuthUrl, pCertificate, pClaimUrl, pClaimIam, pClaimMemberId) {
        this.validationAuthUrl = pAuthUrl;
        this.validationPublicKey = pCertificate;
        this.claimUrl = pClaimUrl;
        this.claimIam = pClaimIam;
        this.claimMemberId = pClaimMemberId;
    }
    return UserConfig;
}());
exports.UserConfig = UserConfig;
